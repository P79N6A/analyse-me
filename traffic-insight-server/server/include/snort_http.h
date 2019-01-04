/*
 * @Author: jiamu 
 * @Date: 2018-10-29 10:37:06 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-29 14:54:46
 */

#ifndef _SNORT_HTTP_H_
#define _SNORT_HTTP_H_

#include "im_config.h"
#include "nids.h"


typedef struct
{	
	char strHost[128];
	char strUrl[512];  /*就处理网页那个一般不会太长*/
	uint8_t ucMacAddr[6];
	uint32_t ulTime;
	struct tuple4 addr;
	struct list_head list;
}HTTP_URL_INFO;


int http_insight_init(void *loop);
int start_insight_http(void *pri);
int do_insight_http(void *data,int slDataLen,int slProtocol,
	struct tuple4 *addr,struct ethhdr *pstEthInfo,int direction,NIDS_CONNTRACK_RECORD *pstConn);
#endif
