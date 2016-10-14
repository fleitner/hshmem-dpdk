/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Flavio Leitner <fbl@redhat.com>
 *   Copyright(c) 2013-2014 NEC All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_tailq.h>
#include <rte_pci.h>

#include <rte_hshmem.h>
#include "pmd_hshmem.h"
#include "rte_bulk.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#define HSHMEM_DEBUG(fmt, args...) RTE_LOG(DEBUG, PMD, fmt, ## args)

/* Red Hat, ivshmem device */
#define HSHMEM_VENDOR_ID 0x1AF4
#define HSHMEM_DEVICE_ID 0x1110

#define HSHMEM_TXQ_MAX 1
#define HSHMEM_RXQ_MAX 1

#define HSHMEM_LINK_FULL_DUPLEX 2
#define HSHMEM_LINK_SPEED_10G 10000

#define RING_FREE_THRESHOLD 255
#define MAX_BURST 64

struct hshmem_adapter {
	struct rte_ring *rxring;
	struct rte_ring *rxfreering;
	struct rte_ring *txring;
	struct rte_ring *txfreering;
	struct rte_mempool *mp;
	int stopped;
	struct hshmem_header *header;
	uint8_t mac_addr[ETHER_ADDR_LEN];
	void *ivshmem;
	phys_addr_t *pa;
	void *va;
};
/* FIXME: RTE_BUILD_BUG_ON(sizeof(struct hshmem_adapter) > PAGE_SIZE); */

struct hshmem_pkt_pmd {
	struct hshmem_pkt pkt;
	struct rte_mbuf *mbuf;
} __attribute__((__packed__));

static struct hshmem_adapter *
get_adapter(struct rte_eth_dev *eth_dev)
{
	return eth_dev->data->dev_private;
}

static struct rte_ring *
get_ptr_align(struct rte_ring *prev, size_t size, int align)
{
	return RTE_PTR_ALIGN(RTE_PTR_ADD(prev, size), align);
}

static void *
get_va_align(struct rte_ring *prev, size_t size, int align)
{
	return RTE_PTR_ALIGN(RTE_PTR_ADD(prev, size), align);
}

/* FIXME: move to the lib */
static uint32_t
get_ring_offset(struct hshmem_adapter *adapter, struct rte_ring *ring)
{
	return (char *)ring - (char *)adapter->ivshmem;
}

static struct hshmem_pkt_pmd *
__get_pkt_pmd(struct rte_mbuf *mbuf)
{
	return (struct hshmem_pkt_pmd *)rte_mbuf_to_baddr(mbuf);

}

static struct hshmem_pkt_pmd *
hshmem_get_pkt_pmd(struct rte_mbuf *mbuf)
{
	struct hshmem_pkt_pmd *pkt = __get_pkt_pmd(mbuf);

	pkt->pkt.reserved = 0;
	pkt->pkt.len = rte_pktmbuf_pkt_len(mbuf);
	pkt->mbuf = mbuf;

	return pkt;
}

/*
 * the pfn (page frame number) are bits 0-54 (see pagemap.txt in linux
 * Documentation).
 */
#define	PAGEMAP_PFN_BITS	54
#define	PAGEMAP_PFN_MASK	RTE_LEN2MASK(PAGEMAP_PFN_BITS, phys_addr_t)

static int
get_phys_map(void *va, phys_addr_t pa[], uint32_t pg_num, uint32_t pg_sz)
{
	int32_t rc, fd;
	uint32_t i, nb;
	off_t ofs;

	ofs = (uintptr_t)va / pg_sz * sizeof(*pa);
	nb = pg_num * sizeof(*pa);

	if ((fd = open("/proc/self/pagemap", O_RDONLY)) < 0)
		return ENOENT;

	rc = pread(fd, pa, nb, ofs);
	close(fd);
	if (rc < 0 || (rc -= nb) != 0) {
		RTE_LOG(ERR, PMD, "failed read of %u bytes from pagemap "
			"at offset %zu, error code: %d\n",
			nb, (size_t)ofs, errno);
		return ENOENT;
	}

	for (i = 0; i != pg_num; i++) {
		pa[i] = (pa[i] & PAGEMAP_PFN_MASK) * pg_sz;
	}

	return 0;
}

static int
hshmem_dev_configure(__rte_unused struct rte_eth_dev *dev)
{
	HSHMEM_DEBUG("hshmem: configure OK\n");

	return 0;
}

static int
hshmem_dev_start(struct rte_eth_dev *dev)
{
	struct hshmem_adapter *adapter = get_adapter(dev);

	adapter->stopped = 0;
	/* FIXME: barrier? */

	return 0;
}

static void
hshmem_dev_stop(struct rte_eth_dev *dev)
{
	struct hshmem_adapter *adapter = get_adapter(dev);

	adapter->stopped = 1;
	/* FIXME: barrier? */

	return;
}

static void
hshmem_dev_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	dev_info->driver_name = dev->driver->pci_drv.name;
	dev_info->max_rx_queues = HSHMEM_RXQ_MAX;
	dev_info->max_tx_queues = HSHMEM_TXQ_MAX;
	dev_info->min_rx_bufsize = HSHMEM_MIN_FRAME_LEN;
	dev_info->max_rx_pktlen = HSHMEM_MAX_FRAME_LEN;
	dev_info->max_mac_addrs = 1;
}

static void
hshmem_dev_stats_get(__rte_unused struct rte_eth_dev *dev,
		     __rte_unused struct rte_eth_stats *stats)
{
	/* FIXME: Implement */
}

static void
hshmem_dev_stats_reset(__rte_unused struct rte_eth_dev *dev)
{
	/* FIXME: Implement */
}

static int
hshmem_dev_link_update(struct rte_eth_dev *dev,
		       __rte_unused int wait_to_complete)
{
	dev->data->dev_link.link_duplex = HSHMEM_LINK_FULL_DUPLEX;
	dev->data->dev_link.link_speed = HSHMEM_LINK_SPEED_10G;
	dev->data->dev_link.link_status = 1; /* Link is always up */

	return 0;
}

static int
hshmem_dev_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
			  __rte_unused uint16_t nb_rx_desc,
			  __rte_unused unsigned int socket_id,
			  __rte_unused const struct rte_eth_rxconf *rx_conf,
			  __rte_unused struct rte_mempool *mb_pool)
{
	/* Multiqueue not supported */
	HSHMEM_DEBUG("dev %p rxq %d socket: %d\n", dev, rx_queue_id, socket_id);

	if (rx_queue_id != 0)
		return -EINVAL;

	dev->data->rx_queues[rx_queue_id] = get_adapter(dev);

	return 0;
}

static void
hshmem_dev_rx_queue_release(void *rxq)
{
	HSHMEM_DEBUG("hshmem rxq release %p\n", rxq);
}

static int
hshmem_dev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
			  __rte_unused uint16_t nb_tx_desc,
			  __rte_unused unsigned int socket_id,
			  __rte_unused const struct rte_eth_txconf *tx_conf)
{
	/* Multiqueue not supported */
	HSHMEM_DEBUG("dev: %p id: %d socket: %d\n", dev, tx_queue_id, socket_id);

	if (tx_queue_id != 0)
		return -EINVAL;

	dev->data->tx_queues[tx_queue_id] = get_adapter(dev);

	return 0;
}

static void
hshmem_dev_tx_queue_release(void *txq)
{
	HSHMEM_DEBUG("hshmem txq release %p\n", txq);
	return;
}

static struct eth_dev_ops hshmem_eth_dev_ops = {
	.dev_configure          = hshmem_dev_configure,
	.dev_start              = hshmem_dev_start,
	.dev_stop               = hshmem_dev_stop,
	.dev_infos_get          = hshmem_dev_infos_get,
	.stats_get              = hshmem_dev_stats_get,
	.stats_reset            = hshmem_dev_stats_reset,
	.link_update            = hshmem_dev_link_update,
	.mac_addr_add           = NULL,
	.mac_addr_remove        = NULL,
	.rx_queue_setup         = hshmem_dev_rx_queue_setup,
	.rx_queue_release       = hshmem_dev_rx_queue_release,
	.tx_queue_setup         = hshmem_dev_tx_queue_setup,
	.tx_queue_release       = hshmem_dev_tx_queue_release,
};

static inline uint16_t
hshmem_refill_ring(struct rte_mempool *mp, struct rte_ring *ring, int nb_pkts)
{
	struct rte_mbuf *pkts[MAX_BURST];
	int n;
	int bsize;
	int fbufs;

	n = 0;
	while (n < nb_pkts) {
		bsize = RTE_MIN(nb_pkts - n, MAX_BURST);
		fbufs = rte_pktmbuf_alloc_bulk(mp, pkts, bsize);
		rte_ring_sp_enqueue_bulk(ring, (void **)pkts, fbufs);
		n += fbufs;
	}

	return n;
}

static uint16_t
hshmem_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	static struct hshmem_pkt_pmd *hshpkt[MAX_BURST];
	struct hshmem_adapter *adapter = (struct hshmem_adapter *)rx_queue;
	struct rte_ring *rx = adapter->rxring;
	struct rte_ring *rxfree = adapter->rxfreering;
	uint16_t idx;
	uint16_t ndq;

	if (!adapter->stopped)
		return 0;

	if (nb_pkts > MAX_BURST)
		nb_pkts = MAX_BURST;

	ndq = rte_ring_sc_dequeue_burst(rx, (void **)hshpkt, nb_pkts);
	for (idx = 0; idx < ndq; idx++) {
		rx_pkts[idx] = hshpkt[idx]->mbuf;
		rx_pkts[idx]->pkt_len = hshpkt[idx]->pkt.len;
		rx_pkts[idx]->data_len = hshpkt[idx]->pkt.len;
		rx_pkts[idx]->next = NULL;
	}

	if (rte_ring_free_count(rxfree) > RING_FREE_THRESHOLD)
		hshmem_refill_ring(adapter->mp, rxfree, RING_FREE_THRESHOLD);

	return ndq;
}

static uint16_t
hshmem_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct hshmem_adapter *adapter = (struct hshmem_adapter *)tx_queue;
	struct rte_ring *tx = adapter->txring;
	struct rte_ring *txfree = adapter->txfreering;
	struct rte_mbuf *mbuf;
	struct hshmem_pkt_pmd *pkt;
	uint16_t i;
	uint16_t cnt;

	if (!adapter->stopped)
		return 0;

	cnt = 0;
	i = 0;
	while (i < nb_pkts) {
		mbuf = tx_pkts[i++];
		pkt = hshmem_get_pkt_pmd(mbuf);
		if (rte_ring_sp_enqueue(tx, pkt)) {
			rte_pktmbuf_free(mbuf);
			continue;
		}

		cnt++;
	}

	i = RTE_MIN(rte_ring_count(txfree), (unsigned int)RING_FREE_THRESHOLD);
	while (i > 0) {
		rte_ring_sc_dequeue(txfree, (void **)&mbuf);
		rte_pktmbuf_free(mbuf);
		i--;
	}

	return cnt;
}

static int
hshmem_eth_dev_uninit(__rte_unused struct rte_eth_dev *eth_dev)
{
	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
		return -EPERM;

	/* FIXME: :-) */
	return 0;
}

static void
hshmem_set_macaddr(struct rte_eth_dev *eth_dev)
{
	struct hshmem_adapter *adapter = get_adapter(eth_dev);

	eth_random_addr(&adapter->mac_addr[0]);
	eth_dev->data->mac_addrs = (struct ether_addr *)adapter->mac_addr;
}

static int
hshmem_init_queue_rings(struct hshmem_adapter *adapter)
{
	unsigned int ring_flags = RING_F_SP_ENQ | RING_F_SC_DEQ;
	size_t ring_size = rte_ring_get_memsize(HSHMEM_MAX_PACKETS);
	size_t size;
	int ret;

	/* RX Ring */
	adapter->rxring = get_ptr_align(adapter->ivshmem, PAGE_SIZE, PAGE_SIZE);
	ret = rte_ring_init(adapter->rxring, "hshmem_rxring",
			    HSHMEM_MAX_PACKETS, ring_flags);
	if (ret < 0) {
		RTE_LOG(ERR, PMD, "Unable initialize rxring %d\n", ret);
		return ret;
	}

	/* RX Free Ring */
	size = ring_size + RTE_CACHE_LINE_SIZE;
	adapter->rxfreering = get_ptr_align(adapter->rxring, size,
					    RTE_CACHE_LINE_SIZE);
	ret = rte_ring_init(adapter->rxfreering, "hshmem_rxfreering",
			    HSHMEM_MAX_PACKETS, ring_flags);
	if (ret < 0) {
		RTE_LOG(ERR, PMD, "Unable initialize rxfreering %d\n", ret);
		return ret;
	}

	/* TX Ring */
	adapter->txring = get_ptr_align(adapter->rxfreering, size,
					RTE_CACHE_LINE_SIZE);
	ret = rte_ring_init(adapter->txring, "hshmem_txring",
			    HSHMEM_MAX_PACKETS, ring_flags);
	if (ret < 0) {
		RTE_LOG(ERR, PMD, "Unable initialize txring %d\n", ret);
		return ret;
	}

	/* TX Free Ring */
	adapter->txfreering = get_ptr_align(adapter->txring, size,
					    RTE_CACHE_LINE_SIZE);
	ret = rte_ring_init(adapter->txfreering, "hshmem_txfreering",
			    HSHMEM_MAX_PACKETS, ring_flags);
	if (ret < 0) {
		RTE_LOG(ERR, PMD, "Unable initialize txfreering %d\n", ret);
		return ret;
	}

	/* the mp is located right after txfreering */
	adapter->va = get_va_align(adapter->txfreering, size, PAGE_SIZE);

	return 0;
}

static int
hshmem_init_header(struct hshmem_adapter *adapter)
{
	struct hshmem_header *header = adapter->ivshmem;

	memset(header, 0, sizeof(struct hshmem_header));
	header->sequential = 1;
	header->version = HSHMEM_VERSION;
	header->rxring_offset = get_ring_offset(adapter, adapter->rxring);
	header->rxfreering_offset = get_ring_offset(adapter,
						    adapter->rxfreering);

	header->txring_offset = get_ring_offset(adapter, adapter->txring);
	header->txfreering_offset = get_ring_offset(adapter,
						    adapter->txfreering);
	rte_wmb();
	header->magic = HSHMEM_MAGIC;

	return 0;

}

static int
hshmem_init_mempool(struct hshmem_adapter *adapter)
{
	unsigned int flags = 0; /* MEMPOOL_F_NO_SPREAD? */
	struct rte_mempool *mp;
	uint32_t pg_num, pg_shift, pg_sz, total_size;
	uint32_t elt_size = sizeof(struct hshmem_pkt_pmd);
	uint32_t elt_num;
	size_t sz;
	phys_addr_t *pa;
	void *va = adapter->va;
	int rc;

	pg_sz = getpagesize();
	pg_shift = rte_bsf32(pg_sz);
	total_size = rte_mempool_calc_obj_size(elt_size, flags, NULL);

	/*
	 * FIXME: estimate according with available mem
	 * 4 busy rings + 1 extra ring for app in-flight
	 */
	elt_num = HSHMEM_MAX_PACKETS * 5;

	/* calc max memory size and max number of pages needed. */
	sz = rte_mempool_xmem_size(elt_num, total_size, pg_shift);
	pg_num = sz >> pg_shift;

	/* extract physical mappings of the allocated memory. */
	pa = calloc(pg_num, sizeof (*pa));
	if (!pa) {
		RTE_LOG(ERR, PMD, "Unable to calloc phys\n");
		return -ENOMEM;
	}

	adapter->pa = pa;
	rc = get_phys_map(va, pa, pg_num, pg_sz);
	if (rc) {
		RTE_LOG(ERR, PMD, "Unable to get phys mapping\n");
		return rc;
	}

	mp = rte_mempool_xmem_create("hshmem_ivshmem", elt_num, elt_size,
				     0, 0, NULL, NULL, NULL, NULL,
				     0, 0, va, pa, pg_num, pg_shift);
	if (!mp) {
		free(pa);
		RTE_LOG(ERR, PMD, "Unable to allocate mempool\n");
		return -ENOMEM;
	}

	RTE_VERIFY(elt_num == mp->size);
	adapter->mp = mp;

	return 0;
}


static int
hshmem_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct hshmem_adapter *adapter;
	struct rte_pci_device *pci_dev;
	char path[PATH_MAX];
	void  *ivshmem;
	int fd;
	int ret;


	eth_dev->dev_ops = &hshmem_eth_dev_ops;
	eth_dev->rx_pkt_burst = &hshmem_recv_pkts;
	eth_dev->tx_pkt_burst = &hshmem_xmit_pkts;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		return 0;
	}

	pci_dev = eth_dev->pci_dev;
	rte_eth_copy_pci_info(eth_dev, pci_dev);

	snprintf(path, sizeof(path),
		 SYSFS_PCI_DEVICES "/" PCI_PRI_FMT "/resource2",
		 pci_dev->addr.domain, pci_dev->addr.bus,
		 pci_dev->addr.devid, pci_dev->addr.function);

	adapter = get_adapter(eth_dev);
	adapter->stopped = 0;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		HSHMEM_DEBUG("Unable to open %s: %d\n", path, fd);
		return fd;
	}

	ivshmem = mmap(NULL, HSHMEM_IVSHMEM_SIZE, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_LOCKED, fd, 0);
	close(fd);
	if (ivshmem == MAP_FAILED) {
		HSHMEM_DEBUG("Unable to mmap %d\n", errno);
		return -EINVAL;
	}

	adapter->ivshmem = ivshmem;

	hshmem_set_macaddr(eth_dev);

	ret = hshmem_init_queue_rings(adapter);
	if (ret < 0)
		return ret;

	ret = hshmem_init_mempool(adapter);

	hshmem_init_header(adapter);

	return ret;
}

static struct rte_pci_id pci_id_hshmem_map[] = {
	{
		.vendor_id = HSHMEM_VENDOR_ID,
		.device_id = HSHMEM_DEVICE_ID,
		.subsystem_vendor_id = PCI_ANY_ID,
		.subsystem_device_id = PCI_ANY_ID,
	},
	{
		.vendor_id = 0,
	},
};

static struct eth_driver rte_hshmem_pmd = {
	{
		.name = "rte_hshmem_pmd",
		.id_table = pci_id_hshmem_map,
	},
	.eth_dev_init = hshmem_eth_dev_init,
	.eth_dev_uninit = hshmem_eth_dev_uninit,
	.dev_private_size = sizeof(struct hshmem_adapter),
};

static int
rte_hshmem_pmd_init(const char *name __rte_unused,
		    const char *param __rte_unused)
{
	rte_eth_driver_register(&rte_hshmem_pmd);

	return 0;
}

static struct rte_driver rte_hshmem_driver = {
	.type = PMD_PDEV,
	.init = rte_hshmem_pmd_init,
};

PMD_REGISTER_DRIVER(rte_hshmem_driver);
