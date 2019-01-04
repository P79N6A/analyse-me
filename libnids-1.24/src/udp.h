/*
 * @Author: jiamu 
 * @Date: 2018-10-16 16:21:07 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-16 17:25:12
 */
#ifndef _NIDS_UDP_H
#define _NIDS_UDP_H
#include <sys/time.h>
#include <linux/if_ether.h>

#if HAVE_BSD_UDPHDR
#define UH_ULEN uh_ulen
#define UH_SPORT uh_sport
#define UH_DPORT uh_dport
#else
#define UH_ULEN len
#define UH_SPORT source
#define UH_DPORT dest
#endif
int udp_init(int size);
void process_udp(char *data,struct ethhdr *pstEthInfo);
void process_udp_timeout(void);
#endif
