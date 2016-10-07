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

#include "pmd_hshmem.h"
#include "hshmem.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#define HSHMEM_DEBUG(fmt, args...) RTE_LOG(DEBUG, PMD, fmt, ## args)

/* Red Hat, ivshmem device */
#define HSHMEM_VENDOR_ID 0x1AF4
#define HSHMEM_DEVICE_ID 0x1110

#define HSHMEM_IVSHMEM_SIZE (16 * 1024 * 1024)

#define HSHMEM_TXQ_MAX 1
#define HSHMEM_RXQ_MAX 1

#define HSHMEM_MTU 1500
#define HSHMEM_MAX_FRAME_LEN (HSHMEM_MTU + ETHER_HDR_LEN \
			      + ETHER_CRC_LEN + VLAN_TAG_SIZE)
#define HSHMEM_MIN_FRAME_LEN 60
#define HSHMEM_MAX_PACKETS 1024

#define HSHMEM_LINK_FULL_DUPLEX 2
#define HSHMEM_LINK_SPEED_10G 10000

struct hshmem_adapter {
	struct rte_ring *rxring;
	struct rte_ring *rxfreering;
	struct rte_ring *txring;
	struct rte_ring *txfreering;
	int stopped;
	struct rte_mempool *mp;
	struct hshmem_header *header;
	struct ether_addr mac_addr;
	void *ivshmem;
};
RTE_BUILD_BUG_ON(sizeof(struct hshmem_adapter) > PAGE_SIZE);

struct hshmem_pkt_pmd {
	struct rte_mbuf *mb;
	struct hshmem_pkt pkt;
} __attribute__((__packed__));
RTE_BUILD_BUG_ON(sizeof(struct hshmem_pkt_pmd) > RTE_PKTMBUF_HEADROOM);

static struct hshmem_adapter *
get_adapter(struct rte_eth_dev *eth_dev)
{
	return eth_dev->data->dev_private;
}

static struct rte_ring *
get_ptr_align(struct rte_ring *ring, size_t size, int align)
{
	return RTE_PTR_ALIGN(RTE_PTR_ADD(ivshmem, size), align);
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

	/* invalidate */
	adapter->nic->hdr.valid = 0;
	barrier();
	/* reset */
	adapter->nic->hdr.reset = 1;
	/* no need to wait here */
	adapter->up_idx = adapter->down_idx = 0;

	return 0;
}

static void
hshmem_dev_stop(struct rte_eth_dev *dev)
{
	struct hshmem_adapter *adapter = get_adapter(dev);

	adapter->stopped = 1;

	return;
}

static void
hshmem_dev_infos_get(__rte_unused struct rte_eth_dev *dev,
		     struct rte_eth_dev_info *dev_info)
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
}

static void
hshmem_dev_stats_reset(__rte_unused struct rte_eth_dev *dev)
{
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
hshmem_dev_rx_queue_setup(__rte_unused struct rte_eth_dev *dev,
			  uint16_t rx_queue_id,
			  __rte_unused uint16_t nb_rx_desc,
			  __rte_unused unsigned int socket_id,
			  __rte_unused const struct rte_eth_rxconf *rx_conf,
			  __rte_unused struct rte_mempool *mb_pool)
{
	/* Multiqueue not supported */
	HSHMEM_DEBUG("rxq: %p id: %d socket: %d\n", q, rx_queue_id, socket_id);
	return 0;
}

static void
hshmem_dev_rx_queue_release(void *rxq)
{
	/* Multiqueue not supported */
	HSHMEM_DEBUG("rxq: %p\n", rxq);
	return 0;
}

static int
hshmem_dev_tx_queue_setup(struct rte_eth_dev *dev,
			  uint16_t tx_queue_id,
			  __rte_unused uint16_t nb_tx_desc,
			  unsigned int socket_id,
			  __rte_unused const struct rte_eth_txconf *tx_conf)
{
	/* Multiqueue not supported */
	HSHMEM_DEBUG("dev: %p id: %d socket: %d\n", q, tx_queue_id, socket_id);
	return 0;
}

static void
hshmem_dev_tx_queue_release(__rte_unused void *txq)
{
	/* Multiqueue not supported */
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

static uint16_t
hshmem_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct hshmem_queue *q = (struct hshmem_queue *)rx_queue;
	struct hshmem_adapter *adapter = q->adapter;
	struct hshmem_data *data = &adapter->nic->up;
	struct hshmem_packet *p;
	struct rte_mbuf *mb;
	uint16_t nr;
	int idx;

	if (!adapter->nic->hdr.valid)
		return 0;

	idx = adapter->up_idx;
	for (nr = 0; nr < nb_pkts; nr++) {
		p = &data->packets[idx];
		if (p->status != HSHMEM_PKT_ST_FILLED)
			break;
		mb = rte_pktmbuf_alloc(adapter->mp);
		if (!mb)
			break;

		rte_memcpy(rte_pktmbuf_mtod(mb, void *), p->data, p->len);
		mb->pkt.in_port = q->port_id;
		mb->pkt.nb_segs = 1;
		mb->pkt.next = NULL;
		mb->pkt.pkt_len = p->len;
		mb->pkt.data_len = p->len;
		rx_pkts[nr] = mb;

		barrier();
		p->status = HSHMEM_PKT_ST_FREE;

		if (++idx >= HSHMEM_NR_PACKET)
			idx = 0;
	}

	adapter->up_idx = idx;

	return nr;
}

static uint16_t
hshmem_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
       struct hshmem_queue *q = (struct hshmem_queue *)tx_queue;
       struct hshmem_adapter *adapter = q->adapter;
       struct hshmem_data *data = &adapter->nic->down;
       struct hshmem_packet *p;
       uint16_t nr;
       int idx, old;

       if (!adapter->nic->hdr.valid)
               return 0;

       for (nr = 0; nr < nb_pkts; nr++) {
               int len = rte_pktmbuf_data_len(tx_pkts[nr]);
               if (len > HSHMEM_MAX_FRAME_LEN)
                       break;
retry:
               idx = ACCESS_ONCE(adapter->down_idx);
               p = &data->packets[idx];
               old = cmpxchg(&p->status, HSHMEM_PKT_ST_FREE, HSHMEM_PKT_ST_USED
);
               if (old != HSHMEM_PKT_ST_FREE) {
                       if (old == HSHMEM_PKT_ST_FILLED &&
                                       idx == ACCESS_ONCE(adapter->down_idx)) {
                               break;
                       }
                       goto retry;
               }

               if (++idx >= HSHMEM_NR_PACKET)
                       idx = 0;
               adapter->down_idx = idx;

               p->len = len;

               rte_memcpy(p->data, rte_pktmbuf_mtod(tx_pkts[nr], void *), len);

               barrier();
               p->status = HSHMEM_PKT_ST_FILLED;

               rte_pktmbuf_free(tx_pkts[nr]);
       }

       return nr;
}

static int
hshmem_eth_dev_uninit(struct rte_eth_dev *eth_dev)
{
	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
		return -EPERM;

	/* FIXME: :-) */
	return 0;
}

static int
hshmem_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct hshmem_adapter *adapter;
	struct rte_pci_device *pci_dev;
	char path[PATH_MAX];
	void  *ivshmem; 
	unsigned int ring_flags;
	size_t ring_size;
	size_t size;
	int ret;


	eth_dev->dev_ops = &hshmem_eth_dev_ops;
	eth_dev->rx_pkt_burst = &hshmem_recv_pkts;
	eth_dev->tx_pkt_burst = &hshmem_xmit_pkts;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
                return 0;
	}

	pci_dev = eth_dev->pci_dev;
	rte_eth_copy_pci_info(eth_dev, pci_dev);

	rte_snprintf(path, sizeof(path),
		     SYSFS_PCI_DEVICES "/" PCI_PRI_FMT "/resource2",
		     dev->addr.domain, dev->addr.bus,
		     dev->addr.devid, dev->addr.function);

	adapter = get_adapter(eth_dev);
	adapter->stopped = 0

	ret = open(path, O_RDWR);
	if (ret < 0) {
		HSHMEM_DEBUG("Not found %s\n", path);
		return -ENODEV;
	}
	ivshmem = mmap(NULL, HSHMEM_IVSHMEM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED,
	 	       ret, 0);
	if (ivshmem == MAP_FAILED) {
		HSHMEM_DEBUG("Unable to mmap %d\n", errno);
		close(ret);
		return -ENODEV;
	}
	close(ret);

	adapter->ivshmem = ivshmem;
	adapter->header = ivshmem;
	
	eth_random_addr(&adapter->mac_addr[0]);
	ether_addr_copy(adapter->mac_addr, &eth_dev->data->mac_addrs[0]);

	/* RX Ring */
	ring_flags = RING_F_SP_ENQ | RING_F_SC_DEQ;
	adapter->rxring = get_ptr_align(ivshmem, PAGE_SIZE, PAGE_SIZE);
	ret = rte_ring_init(adapter->rxring, "hshmem_rxring",
			    HSHMEM_MAX_PACKETS, ring_flags);
	if (ret < 0) {
		HSHMEM_DEBUG("Unable initialize rxring %d\n", ret);
		return -ENODEV;
	}

	/* RX Free Ring */
	ring_size = rte_ring_get_memsize(HSHMEM_MAX_PACKETS);
	size = ring_size + RTE_CACHE_LINE_SIZE;
	adapter->rxfreering = get_ptr_align(adapter->rxring, size,
					    RTE_CACHE_LINE_SIZE);
	ret = rte_ring_init(adapter->rxfreering, "hshmem_rxfreering",
			    HSHMEM_MAX_PACKETS, ring_flags);
	if (ret < 0) {
		HSHMEM_DEBUG("Unable initialize rxfreering %d\n", ret);
		return -ENODEV;
	}

	/* TX Ring */
	adapter->txring = get_ptr_align(adapter->rxfreering, size,
					RTE_CACHE_LINE_SIZE);
	ret = rte_ring_init(adapter->txring, "hshmem_txring",
			    HSHMEM_MAX_PACKETS, ring_flags);
	if (ret < 0) {
		HSHMEM_DEBUG("Unable initialize txring %d\n", ret);
		return -ENODEV;
	}

	/* TX Free Ring */
	adapter->txfreering = get_ptr_align(adapter->txring, size,
					    RTE_CACHE_LINE_SIZE);
	ret = rte_ring_init(adapter->txfreering, "hshmem_txfreering",
			    HSHMEM_MAX_PACKETS, ring_flags);
	if (ret < 0) {
		HSHMEM_DEBUG("Unable initialize txfreering %d\n", ret);
		return -ENODEV;
	}

	adapter->mp = get_ptr_align(adapter->txfreering, size, PAGE_SIZE);
	

	return 0;
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

extern struct pci_device_list device_list;

static void eth_hshmem_probe(struct rte_pci_device *dev)
{
	char path[PATH_MAX];

	HSHMEM_DEBUG("%x:%x\n", dev->id.vendor_id, dev->id.device_id);

	if (dev->id.vendor_id != 0x1af4 || dev->id.device_id != 0x1110)
		return;

	HSHMEM_DEBUG("FOUND DEVICE: " PCI_PRI_FMT "\n",
		     dev->addr.domain, dev->addr.bus,
		     dev->addr.devid, dev->addr.function);

	rte_snprintf(path, sizeof(path),
		     SYSFS_PCI_DEVICES "/" PCI_PRI_FMT "/driver",
		     dev->addr.domain, dev->addr.bus,
		     dev->addr.devid, dev->addr.function);
	if (access(path, F_OK) == 0) {
		RTE_LOG(ERR, PMD,
			"%s: Device is bound to kernel driver\n",
			dev->data->name);
		return;
	}

	rte_hshmem_pmd.pci_drv.devinit(&rte_hshmem_pmd.pci_drv, dev);
}

int rte_hshmem_probe(void)
{
	struct rte_pci_device *dev = NULL;

	TAILQ_FOREACH(dev, &device_list, next)
		eth_hshmem_probe(dev);

	return 0;
}

int rte_hshmem_pmd_init(void)
{
	rte_eth_driver_register(&rte_hshmem_pmd);

	return 0;
}
