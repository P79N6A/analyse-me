/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:27:52
 */

#include "protocol.h"

#define TC58_ENTRY_NUM		(8)
#define TC58_SIZE_MAX		(32)
#define TC58_SND_CYCLE	(HZ << 5) /* 32s */
#define TC58_BUF_SIZE		(TC58_ENTRY_NUM * TC58_SIZE_MAX)
#define TC58_NUMLEN_MIN	(5)
#define TC58_NUMLEN_MAX	(11)

static int do_tc58_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    	if (priv->prd) {
		int			size = 0;
		const char	*ptr;
#if 0
		printpkt("patern:%s data:%s\n ht:%x %x %d %d len:%d\n"
			,((content_match_t *)(priv->r->ds_list[0]))->pattern_buf
			,priv->prd ? priv->prd : "NULL"
			,priv->ht.isrc, priv->ht.idst
			,priv->ht.psrc, priv->ht.pdst
			,priv->skb->len);
#endif
		skip_space(priv->prd);
		ptr = priv->prd;

		while (*ptr != '&' && *ptr != ' ' && *ptr != ';' && *ptr != 0x0d && *ptr != 0x0a
			&& *ptr != 0 && size < TC58_SIZE_MAX && ptr < priv->end) {
			ptr++, size++;
		}
		
		if (size && size < TC58_SIZE_MAX) {
			// priv->ptl->msg.mc_add(priv->ptl, TC58
			// 			, priv->prd, size, ip, mac);
            unsigned char buf[TC58_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("tc58-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}

	return -1;
}

PROTOCOL_CONTORL_INFO stTC58CtrlInfo = {
    .strName        = "TC58",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_tc58_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
