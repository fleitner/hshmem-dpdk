# HSHMEM PMD

HSHMEM Poll Mode Driver for DPDK 16.07

## How to use

You need some workaround to use it in original DPDK, because DPDK cannot
recognize HSHMEM device which is available as shared memory in VM.

1. Copy all files to your DPDK application directory.

2. Add pmd_memnic.c to SRCS-y in Makefile.

3. Call rte_memnic_pmd_init() just after rte_pmd_init_all(), to initialize
   PMD for HSHMEM.

4. Call rte_memnic_probe() after rte_eal_pci_probe(), to probe HSHMEM
   device from IVSHMEM.

After HSHMEM device successfully found, you can use it as existing way.
You can receive a packet with rte_eth_rx_burst() and send a packet with
rte_eth_tx_burst().
