/*
 * @Author: jiamu 
 * @Date: 2018-10-16 16:21:04 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-16 17:21:59
 */
#include <config.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include "checksum.h"
#include "scan.h"
#include "udp.h"
#include "util.h"
#include "nids.h"
#include "hash.h"

extern struct proc_node *udp_procs;


static struct hlist_head *pstUdpconnHead = NULL;
static int udp_num = 0;
static int udp_stream_table_size;
static int max_stream;

/**
 * @brief 
 * 	udp init
 * 	need after tcp_init
 * @param size 
 * @return int 
 */
int udp_init(int size)
{
    int i = 0;
    udp_stream_table_size = size;
    pstUdpconnHead = calloc(udp_stream_table_size, sizeof(struct hlist_head));
    memset(pstUdpconnHead,0,udp_stream_table_size * sizeof(struct hlist_head));
}

static int mk_hash_index(struct tuple4 addr)
{
    int hash=mkhash(addr.saddr, addr.source, addr.daddr, addr.dest);
    return hash % udp_stream_table_size;
}
inline void free_conn(NIDS_UDP_CONNTRACK *pstFindConn)
{
	if(pstFindConn->stConnInfo.callClose)
	{
		pstFindConn->stConnInfo.callClose(pstFindConn);
	}
	if(pstFindConn->stConnInfo.ucData)
	{
		free(pstFindConn->stConnInfo.ucData);
	}
	free(pstFindConn);
}

static  NIDS_UDP_CONNTRACK *nids_find_udp_conn(struct tuple4 *addr)
{
    int hash_index = 0;
	unsigned int timestatmp = time(NULL);

	struct tuple4 hashaddr = *addr;
    NIDS_UDP_CONNTRACK *pstFindConn = NULL;
    hash_index = mk_hash_index(hashaddr);
    struct hlist_head *pstUdpFindTmp = pstUdpconnHead + hash_index;

	struct hlist_node *next, *tmp;
    hlist_for_each_entry_safe(pstFindConn,next,tmp,pstUdpFindTmp, hlist) 
	{
		if(memcmp(&pstFindConn->addr, addr, sizeof (struct tuple4)) == 0)
		{
			pstFindConn->bitActive   = 1;
			pstFindConn->ulTimeStamp = timestatmp;
			return pstFindConn;
		}
		/*connetc overtime*/
		//if(timestatmp > NIDS_CONN_OVERTIME && ((timestatmp - NIDS_CONN_OVERTIME) > pstFindConn->ulTimeStamp))
		if((pstFindConn->ulTimeStamp + NIDS_CONN_OVERTIME) < timestatmp)
		{
			hlist_del(&pstFindConn->hlist);
			//printf("Line %d ,free conn port %d <--> port %d ,time %u now %u \n",__LINE__,addr->dest,addr->source,pstFindConn->ulTimeStamp,timestatmp);
			free_conn(pstFindConn);
		}
	}

	hashaddr.source =  addr->dest;
  	hashaddr.dest   =  addr->source;
  	hashaddr.saddr  =  addr->daddr;
  	hashaddr.daddr  =  addr->saddr;
    hash_index = mk_hash_index(hashaddr);

	pstUdpFindTmp = pstUdpconnHead + hash_index;
	hlist_for_each_entry_safe(pstFindConn,next,tmp,pstUdpFindTmp, hlist) 
	{
		if(memcmp(&pstFindConn->addr, addr, sizeof (struct tuple4)) == 0)
		{
			pstFindConn->bitActive   = 1;
			pstFindConn->ulTimeStamp = timestatmp;
			return pstFindConn;
		}
		/*connetc overtime*/
		if((pstFindConn->ulTimeStamp + NIDS_CONN_OVERTIME) < timestatmp)
		{
			hlist_del(&pstFindConn->hlist);
			//printf("Line %d ,free conn port %d <--> port %d ,time %u now %u \n",__LINE__,addr->dest,addr->source,pstFindConn->ulTimeStamp,timestatmp);
			free_conn(pstFindConn);
		}
	}

	pstFindConn = calloc(1,sizeof(*pstFindConn));
	if(pstFindConn == NULL)
	{
		return NULL;
	}
	memset(pstFindConn,0,sizeof(*pstFindConn));
	
	pstFindConn->stConnInfo.eMainType     = CONN_MAIN_INVALID;
	pstFindConn->addr 					  = *addr;
	pstFindConn->bitActive   			  = 1;
	pstFindConn->ulTimeStamp 			  = timestatmp;
	hlist_add_head(&pstFindConn->hlist, pstUdpFindTmp);
	
    return pstFindConn;
}

void process_udp(char *data,struct ethhdr *pstEthInfo)
{
    struct proc_node *ipp = udp_procs;
    struct ip *iph = (struct ip *) data;
    struct udphdr *udph;
    struct tuple4 addr;
    int hlen = iph->ip_hl << 2;
    int len = ntohs(iph->ip_len);
    int ulen;
    if (len - hlen < (int)sizeof(struct udphdr))
	return;
    udph = (struct udphdr *) (data + hlen);
    ulen = ntohs(udph->UH_ULEN);
    if (len - hlen < ulen || ulen < (int)sizeof(struct udphdr))
	return;
    /* According to RFC768 a checksum of 0 is not an error (Sebastien Raveau) */
    if (udph->uh_sum && my_udp_check
	((void *) udph, ulen, iph->ip_src.s_addr,
	 iph->ip_dst.s_addr)) return;
    addr.source = ntohs(udph->UH_SPORT);
    addr.dest = ntohs(udph->UH_DPORT);
    addr.saddr = iph->ip_src.s_addr;
    addr.daddr = iph->ip_dst.s_addr;
    
    if (!nids_params.net_filter(iph, len,udph,IPPROTO_UDP))
	    return;

	NIDS_UDP_CONNTRACK * pstStreamConn= nids_find_udp_conn(&addr);
	if(NULL == pstStreamConn)
	{
		/*no record data and add new failed*/
		syslog(nids_params.syslog_level, "no record udp data and add new failed\n");
		return;
	}
	
    while (ipp) {
	ipp->item(&addr, ((char *) udph) + sizeof(struct udphdr),
		  ulen - sizeof(struct udphdr), data,pstEthInfo,&pstStreamConn->stConnInfo);
	ipp = ipp->next;
    }
}

void process_udp_timeout(void)
{
	int i = 0;
	NIDS_UDP_CONNTRACK *pstFindConn = NULL;
	unsigned int timestatmp = time(NULL);
	struct hlist_head *pstUdpFindTmp = pstUdpconnHead;
    for(i = 0;i < udp_stream_table_size;i++,pstUdpFindTmp++)
	{
		struct hlist_node *next, *tmp;
		hlist_for_each_entry_safe(pstFindConn,next,tmp,pstUdpFindTmp, hlist) 
		{
			/*connetc overtime*/
			//if(timestatmp > NIDS_CONN_OVERTIME && ((timestatmp - NIDS_CONN_OVERTIME) > pstFindConn->ulTimeStamp))
			if((pstFindConn->ulTimeStamp + NIDS_CONN_OVERTIME) < timestatmp)
			{
				hlist_del(&pstFindConn->hlist);
				//printf("Line %d ,free conn port %d <--> port %d,time %u now %u \n",__LINE__,pstFindConn->addr.dest,pstFindConn->addr.source,pstFindConn->ulTimeStamp,timestatmp);
				free_conn(pstFindConn);
			}
		}
	}
}