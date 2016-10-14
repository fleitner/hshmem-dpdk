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
	struct rte_ring *rxring;
	struct rte_ring *rxfreering;
	struct rte_ring *txring;
	struct rte_ring *txfreering;
	int stopped;
	struct hshmem_header *header;
	uint8_t mac_addr[ETHER_ADDR_LEN]; /* FIXME: not used */
	void *ivshmem;
};
static struct rte_ring *
get_ring_ptr(struct rte_hshmem *hshmem, uint32_t offset)
{
	char *ptr = (char *)hshmem->ivshmem + offset;
	return (struct rte_ring *)ptr;
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
	hshmem->rxring = get_ring_ptr(hshmem, header->rxring_offset);
	hshmem->rxfreering = get_ring_ptr(hshmem, header->rxfreering_offset);
	hshmem->txring = get_ring_ptr(hshmem, header->txring_offset);
	hshmem->txfreering = get_ring_ptr(hshmem, header->txfreering_offset);

out:
	return hshmem;

err_supp:
	munmap(ivshmem, HSHMEM_IVSHMEM_SIZE);
err_mmap:
	rte_free(hshmem);
	goto out;
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

int
rte_hshmem_tx(struct rte_hshmem *hshmem, void **pkts, uint16_t nb_pkts)
{

}

int
rte_hshmem_rx(struct rte_hshmem *hshmem, void **pkts, uint16_t nb_pkts)
{

}
