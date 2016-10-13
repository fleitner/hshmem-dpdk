/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Flavio Leitner <fbl@redhat.com>
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

#ifndef __HSHMEM_H__
#define __HSHMEM_H__

#define HSHMEM_MAGIC 0xC0DECAFE
#define HSHMEM_VERSION 0x00000001

#define HSHMEM_MTU 1500
#define VLAN_HLEN 4
#define HSHMEM_MAX_FRAME_LEN (HSHMEM_MTU + ETHER_HDR_LEN + \
			      ETHER_CRC_LEN + VLAN_HLEN)
#define HSHMEM_MIN_FRAME_LEN 60
#define HSHMEM_MAX_PACKETS 1024

/*
 * Shared memory area mapping
 * From guest point of view
 * +------------------+
 * | Header Area      |
 * +------------------+
 * | Padding          |
 * +------------------+
 * | RX Ring          | 
 * +------------------+
 * | Padding          |
 * +------------------+
 * | RX Free Ring     |
 * +------------------+
 * | Padding          |
 * +------------------+
 * | TX Ring          | 
 * +------------------+
 * | Padding          |
 * +------------------+
 * | TX Free Ring     |
 * +------------------+
 * | Padding          |
 * +------------------+
 * | mempoll area     |
 * +------------------+
 */


struct hshmem_header {
	uint32_t magic;			/* feature signature */
	uint32_t version;		/* implementation version */
	uint32_t sequential;		/* data versioning */
	uint32_t features;		/* list of features in the guest */
	uint32_t reserved;		/* not used */
	uint32_t rxring_offset;		/* offset to rxring */
	uint32_t rxfreering_offset;	/* offset to free entries */
	uint32_t txring_offset;		/* offset to txring */
	uint32_t txfreering_offset;	/* offset to free entries */
} __attribute__((__packed__));

struct hshmem_pkt {
	char packet[HSHMEM_MAX_FRAME_LEN];
	uint32_t reserved;
	uint32_t len;
} __attribute__((__packed__));

/* RX direction:
 * Host dequeues allocated but unused buffers from rxfreering
 * Host copies data to the buffer
 * Host enqueues busy buffers to rxring.
 * Guest dequeues busy buffers from rxring.
 * Guest consumes the buffer.
 * Guest returns the buffer to rxfreering.
 *
 * TX direction:
 * Guest enqueues busy buffers to txring.
 * Host dequeues busy buffers from txring.
 * Host copies packets to its memory.
 * Host enqueues unused buffers to txfreering.
 */ 


#endif /* __HSHMEM_H__ */
