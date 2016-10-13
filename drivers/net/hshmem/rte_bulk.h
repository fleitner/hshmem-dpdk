
#define RTE_ASSERT(exp) do { } while(0)
/**
 * Allocate a bulk of mbufs, initialize refcnt and reset the fields to default
 * values.
 *
 *  @param pool
 *    The mempool from which mbufs are allocated.
 *  @param mbufs
 *    Array of pointers to mbufs
 *  @param count
 *    Array size
 *  @return
 *   - 0: Success
 */
static inline int rte_pktmbuf_alloc_bulk(struct rte_mempool *pool,
	 struct rte_mbuf **mbufs, unsigned count)
{
	unsigned idx = 0;
	int rc;

	rc = rte_mempool_get_bulk(pool, (void **)mbufs, count);
	if (unlikely(rc))
		return rc;

	/* To understand duff's device on loop unwinding optimization, see
	 * https://en.wikipedia.org/wiki/Duff's_device.
	 * Here while() loop is used rather than do() while{} to avoid extra
	 * check if count is zero.
	 */
	switch (count % 4) {
	case 0:
		while (idx != count) {
			RTE_ASSERT(rte_mbuf_refcnt_read(mbufs[idx]) == 0);
			rte_mbuf_refcnt_set(mbufs[idx], 1);
			rte_pktmbuf_reset(mbufs[idx]);
			idx++;
	case 3:
			RTE_ASSERT(rte_mbuf_refcnt_read(mbufs[idx]) == 0);
			rte_mbuf_refcnt_set(mbufs[idx], 1);
			rte_pktmbuf_reset(mbufs[idx]);
			idx++;
	case 2:
			RTE_ASSERT(rte_mbuf_refcnt_read(mbufs[idx]) == 0);
			rte_mbuf_refcnt_set(mbufs[idx], 1);
			rte_pktmbuf_reset(mbufs[idx]);
			idx++;
	case 1:
			RTE_ASSERT(rte_mbuf_refcnt_read(mbufs[idx]) == 0);
			rte_mbuf_refcnt_set(mbufs[idx], 1);
			rte_pktmbuf_reset(mbufs[idx]);
			idx++;
		}
	}
	return 0;
}

