/*
 * @Author: jiamu 
 * @Date: 2018-10-17 19:40:24 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:41:56
 */
#include "protocol.h"

#define XC_ENTRY_NUM	(4)
#define XC_SIZE_MAX		(64)
#define XC_SND_CYCLE	(HZ << 5) /* 32s */
#define XC_BUF_SIZE		(XC_ENTRY_NUM * XC_SIZE_MAX)

static int do_xc_action(int actionType,void *data)
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

		while (*ptr != '"' && *ptr != ' ' && *ptr != ';' && *ptr != '&' && *ptr != '%'
			&& *ptr != ','
			&& *ptr != 0 && size < XC_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < XC_SIZE_MAX) {
			// priv->ptl->msg.mc_add(priv->ptl, XC
			// 			, priv->prd, size, ip, mac);
            unsigned char buf[XC_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("xc-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}

	return -1;
}

PROTOCOL_CONTORL_INFO stXCCtrlInfo = {
    .strName        = "XC",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_xc_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
