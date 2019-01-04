/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:45:16
 */

#include "protocol.h"

#define XLWB_ENTRY_NUM	(2)
#define XLWB_SIZE_MAX	(256)
#define XLWB_SND_CYCLE	(HZ << 5) /* 32s */
#define XLWB_BUF_SIZE	(XLWB_ENTRY_NUM * XLWB_SIZE_MAX)

static int do_xlwb_action(int actionType,void *data)
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

		while (*ptr != ' ' && *ptr != ';' && *ptr != '&'
			&& *ptr != '\n' && *ptr != '\r'
			&& *ptr != 0 && size < XLWB_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
	
		/* 20161013, for filter unregister user */
		if (size == 13 && (!memcmp(priv->prd,"100",3))) {
			printpkt("filter unregister user, id[%s]", priv->prd);
			return -1;
		}

		if (size && size < XLWB_SIZE_MAX) {
			// priv->ptl->msg.mc_add(priv->ptl, XLWB
			// 			, priv->prd, size, ip, mac);
            unsigned char buf[XLWB_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("xlwb-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}

	return -1;
}


PROTOCOL_CONTORL_INFO stXLWBCtrlInfo = {
    .strName        = "XLWB",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_xlwb_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
