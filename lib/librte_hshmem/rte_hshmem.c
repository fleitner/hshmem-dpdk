/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Flavio Leitner <fbl@redhat.com>
 *   All rights reserved.
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
 */

#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "rte_hshmem.h"

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

struct rte_hshmem {
	void *ivshmem;
	struct rte_mempool *mempool;
	struct rte_ring *rxring;
	struct rte_ring *rxfreering;
	struct rte_ring *txring;
	struct rte_ring *txfreering;
	int stopped;
	uint8_t mac_addr[ETHER_ADDR_LEN]; /* FIXME: not used */
	struct hshmem_header *header;
};

struct hshmem_pkt *
rte_hshmem_stoh(struct rte_hshmem *hshmem, void *addr)
{
	char *ptr = (char *)hshmem->ivshmem + (uintptr_t)addr;
	return (struct hshmem_pkt *)ptr;
}

void *
rte_hshmem_htos(struct rte_hshmem *hshmem, struct hshmem_pkt *pkt)
{
	uintptr_t offset = (char *)pkt - (char *)hshmem->ivshmem;
	return (void *)offset;
}

uintptr_t
rte_hshmem_ring_htos(struct rte_hshmem *hshmem, struct rte_ring *ring)
{
	return (uintptr_t)ring - (uintptr_t)hshmem->ivshmem;
}

struct rte_ring *
rte_hshmem_ring_stoh(struct rte_hshmem *hshmem, uintptr_t addr)
{
	char *ptr = (char *)hshmem->ivshmem + addr;
	return (struct rte_ring *)ptr;
}

void
rte_hshmem_set_mempool(struct rte_hshmem *hshmem, struct rte_mempool *mempool)
{
	hshmem->mempool = mempool;
}

struct rte_hshmem *
rte_hshmem_open_shmem(const char *path)
{
	struct rte_hshmem *hshmem;
	struct hshmem_header *header;
	void *ivshmem;
	int fd;

	fd = open(path, O_RDWR);
	if (fd == -1)
		goto out;

	hshmem = rte_malloc("rte_hshmem", sizeof(struct rte_hshmem),
			    RTE_CACHE_LINE_SIZE);
	if (!hshmem)
		goto out;

	ivshmem = mmap(NULL, HSHMEM_IVSHMEM_SIZE, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_LOCKED, fd, 0);

	close(fd);

	if (!ivshmem)
		goto err_mmap;

	header = ivshmem;
	if (header->magic != HSHMEM_MAGIC ||
	    header->version != HSHMEM_VERSION)
		goto err_supp;

	hshmem->ivshmem = ivshmem;
	hshmem->header = header;
	hshmem->stopped = 0;
	hshmem->rxring = rte_hshmem_ring_stoh(hshmem, header->rxring_offset);
	hshmem->rxfreering = rte_hshmem_ring_stoh(hshmem,
						  header->rxfreering_offset);
	hshmem->txring = rte_hshmem_ring_stoh(hshmem, header->txring_offset);
	hshmem->txfreering = rte_hshmem_ring_stoh(hshmem,
						  header->txfreering_offset);

out:
	return hshmem;

err_supp:
	munmap(ivshmem, HSHMEM_IVSHMEM_SIZE);
err_mmap:
	rte_free(hshmem);
	return NULL;
}

void
rte_hshmem_close(struct rte_hshmem *hshmem)
{
	munmap(hshmem->ivshmem, HSHMEM_IVSHMEM_SIZE);
	free(hshmem);
}

int
rte_hshmem_get_carrier(struct rte_hshmem *hshmem)
{
	return hshmem->stopped ? 1 : 0;
}

static void
rte_hshmem_copy_from_mbuf(struct hshmem_pkt *pkt, struct rte_mbuf *mbuf)
{
	rte_memcpy(pkt->packet, rte_pktmbuf_mtod(mbuf, char *),
		   mbuf->data_len);
	pkt->len = mbuf->data_len;
}

static void
rte_hshmem_copy_to_mbuf(struct rte_mbuf *mbuf, struct hshmem_pkt *pkt)
{
	rte_memcpy(rte_pktmbuf_mtod(mbuf, char *), pkt->packet, pkt->len);
	mbuf->data_len = pkt->len;
	mbuf->pkt_len = pkt->len;
}

int
rte_hshmem_tx(struct rte_hshmem *hshmem, struct rte_mbuf **pkts,
	      uint16_t nb_pkts)
{
	static void *pktoff[HSHMEM_MAX_BURST];
	struct hshmem_pkt *hshpkt;
	struct rte_ring *rx = hshmem->rxring;
	struct rte_ring *rxfree = hshmem->rxfreering;
	uint16_t idx;
	uint16_t ndq;

	/* FIXME check for stopped ring */

	ndq = rte_ring_sc_dequeue_burst(rxfree, pktoff,
					RTE_MIN(HSHMEM_MAX_BURST, nb_pkts));

	for (idx = 0; idx < ndq; idx++) {
		rte_hshmem_copy_from_mbuf(rte_hshmem_stoh(hshmem, pktoff[idx]),
					  pkts[idx]);
	}

	rte_ring_sp_enqueue_bulk(rx, pktoff, ndq);

	return idx;
}

int
rte_hshmem_rx(struct rte_hshmem *hshmem, struct rte_mbuf **pkts,
	      uint16_t nb_pkts)
{
	static void *pktoff[HSHMEM_MAX_BURST];
	struct hshmem_pkt *hshpkt;
	struct rte_ring *tx = hshmem->txring;
	struct rte_ring *txfree = hshmem->txfreering;
	uint16_t idx;
	uint16_t ndq;
	uint16_t ret;

	/* FIXME check for stopped ring */

	ndq = rte_ring_sc_dequeue_burst(tx, pktoff,
				        RTE_MIN(nb_pkts, HSHMEM_MAX_BURST));

	ret = rte_pktmbuf_alloc_bulk(hshmem->mempool, pkts, ndq);
	if (ret) {
		return 0;
	}

	for (idx = 0; idx < ndq; idx++) {
		rte_hshmem_copy_to_mbuf(pkts[idx],
					rte_hshmem_stoh(hshmem, pktoff[idx]));
	}

	rte_ring_sp_enqueue_bulk(txfree, pktoff, idx);

	return idx;
}
