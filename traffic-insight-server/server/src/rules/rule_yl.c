/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:47:23
 */

#include "protocol.h"

#define YL_ENTRY_NUM	(4)
#define YL_SIZE_MAX		(32)
#define YL_SND_CYCLE	(HZ << 5) /* 32s */
#define YL_BUF_SIZE		(YL_ENTRY_NUM * YL_SIZE_MAX)

static int do_yl_action(int actionType,void *data)
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

		while (*ptr != '@' && *ptr != '%' && *ptr != ';' && *ptr != '&'
			&& *ptr != 0 && *ptr != '"' && size < YL_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < YL_SIZE_MAX) {
			// priv->ptl->msg.mc_add(priv->ptl, YL
			// 			, priv->prd, size, ip, mac);
             unsigned char buf[YL_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("yl-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}

	return -1;
}


PROTOCOL_CONTORL_INFO stYLCtrlInfo = {
    .strName        = "YL",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_yl_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
