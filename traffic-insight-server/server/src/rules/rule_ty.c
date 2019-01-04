/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:33:00
 */

#include "protocol.h"

#define TY_ENTRY_NUM	(4)
#define TY_SIZE_MAX		(32)
#define TY_SND_CYCLE	(HZ << 5) /* 32s */
#define TY_BUF_SIZE		(TY_ENTRY_NUM * TY_SIZE_MAX)

static int do_ty_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    
	if (priv->prd) {
		int			size = 0;
		const char	*ptr;
#if 0
		printpkt("patern:%s data:%s\n ht:%x %x %d %d len:%d"
			,((content_match_t *)(priv->r->ds_list[0]))->pattern_buf
			,priv->prd ? priv->prd : "NULL"
			,priv->ht.isrc, priv->ht.idst
			,priv->ht.psrc, priv->ht.pdst
			,priv->skb->len);
#endif
		skip_space(priv->prd);
		ptr = priv->prd;

		while (*ptr != '"' && *ptr != ';' && *ptr != '&'
			&& *ptr != 0 && size < TY_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < TY_SIZE_MAX) {
			// priv->ptl->msg.mc_add(priv->ptl, TY
			// 			, priv->prd, size, ip, mac);
            unsigned char buf[TY_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("ty-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}

	return -1;	
}
PROTOCOL_CONTORL_INFO stTYCtrlInfo = {
    .strName        = "TY",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_ty_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
