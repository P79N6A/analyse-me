/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:14:12
 */

#include "protocol.h"

#define RJ_ENTRY_NUM	(32)
#define RJ_SIZE_MAX		(16)
#define RJ_SND_CYCLE	(HZ << 5) /* 32s */
#define RJ_BUF_SIZE		(RJ_ENTRY_NUM * RJ_SIZE_MAX)
#define RJ_NUMLEN_MIN	(5)
#define RJ_NUMLEN_MAX	(11)

static int do_rj_action(int actionType,void *data)
{
    m_priv_t *priv	= data;

    if (priv->prd) {
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

		while (*ptr != '@' && *ptr != ' ' && *ptr != ';' && *ptr != '&'
			&& *ptr != 0 && size < RJ_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < RJ_SIZE_MAX
			&& _is_all_digit(priv->prd, size, RJ_SIZE_MAX)) {
			// priv->ptl->msg.mc_add(priv->ptl, RJ
			// 			, priv->prd, size, ip, mac);
            unsigned char buf[RJ_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("RJ-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}

	return -1;
}

PROTOCOL_CONTORL_INFO stRJCtrlInfo = {
    .strName        = "RJ",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_rj_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
