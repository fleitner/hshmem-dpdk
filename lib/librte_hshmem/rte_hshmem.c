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
	uint8_t mac_addr[ETHER_ADDR_LEN];
	void *ivshmem;
};


struct rte_hshmem *
rte_hshmem_open_shmem(const char *path)
{
	/* file exists? */
	/* open the file */
	/* mmap the file */
	/* close the fd */
	/* read the header */
	/* sanity check */
	/* return the opaque handler */
	return NULL;
}

void
rte_hshmem_close(struct rte_hshmem *hshmem)
{
	free(hshmem->ivshmem);
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
