/*
 * @Author: mikey.zhaopeng 
 * @Date: 2018-10-12 10:45:50 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-19 16:31:22
 */


#include "protocol.h"


// static int    slInitFlg  = 0;
// static int    slEntryNum = 0;
// static struct list_head msglist;

#define WCHAT_ENTRY_NUM		(32)
#define WCHAT_SIZE_MAX		(16)
#define WCHAT_SIZE_MIN			(5)
#define WCHAT_SND_CYCLE		(HZ << 5) /* 32s */
#define WCHAT_BUF_SIZE		(WCHAT_ENTRY_NUM * WCHAT_SIZE_MAX)


static int do_wechat_action(int actionType,void *data)
{
    //printf("Now get one wechat data stream \n");
    char strMsg[WCHAT_SIZE_MAX + 10] = {0};
    
    m_priv_t *priv	= data;

	if (priv->prd) {
		//printf("Now get one wechat data stream priv->prd %s \n",priv->prd);
		int			size = 0;
		const char	*ptr;
#if 0
		print("patern:%s data:%s\n ht:%x %x %d %d len:%d"
			,((content_match_t *)(priv->r->ds_list[0]))->pattern_buf
			,priv->prd ? priv->prd : "NULL"
			,priv->ht.isrc, priv->ht.idst
			,priv->ht.psrc, priv->ht.pdst
			,priv->skb->len);
#endif
		skip_space(priv->prd);
		ptr = priv->prd;

		while (*ptr != '}' && *ptr != ';' && *ptr != '&' && *ptr != 0
				&& size < WCHAT_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size > WCHAT_SIZE_MIN && _is_all_digit(priv->prd, size, WCHAT_SIZE_MAX)) {
			
            memcpy(strMsg,priv->prd,size);
			do_record_data(strMsg,strlen(strMsg),priv);

            // printf("wechat >>> priv->prd = %s  srcmac-->%02x:%02x:%02x:%02x:%02x:%02x dstmac-->%02x:%02x:%02x:%02x:%02x:%02x srcip-->%08x dstip:%08x \n",
			// 	strMsg,
			// 	priv->stEthInfo.h_source[0],priv->stEthInfo.h_source[1],priv->stEthInfo.h_source[2],
			// 	priv->stEthInfo.h_source[3],priv->stEthInfo.h_source[4],priv->stEthInfo.h_source[5],

			// 	priv->stEthInfo.h_dest[0],priv->stEthInfo.h_dest[1],priv->stEthInfo.h_dest[2],
			// 	priv->stEthInfo.h_dest[3],priv->stEthInfo.h_dest[4],priv->stEthInfo.h_dest[5],
				
			// 	priv->ht.saddr,priv->ht.daddr
			// 	);
			return RET_SUCCESS;
		}
	}
    //printf("priv->prd = %s  \n",priv->prd);
    return RET_FAILED;
}

static int do_wechat_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stWECHATCtrlInfo = {
    .strName        = "WECHAT",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_wechat_action,
    .cbProtoPack    = do_wechat_pack,
    .private        = NULL
};

