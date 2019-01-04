/*
 * @Author: jiamu 
 * @Date: 2018-10-17 15:13:41 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 15:23:20
 */
#include "protocol.h"

#define BDTB_ENTRY_NUM	(4)
#define BDTB_SIZE_MAX	(64)
#define BDTB_SND_CYCLE	(HZ << 5) /* 32s */
#define BDTB_BUF_SIZE	(BDTB_ENTRY_NUM * BDTB_SIZE_MAX)

static int do_bdtb_action(int actionType,void *data)
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

		while (*ptr != '\n' && *ptr != '\r' && *ptr != ';' && *ptr != '&' 
			&& *ptr != '_' && *ptr != ' '
			&& *ptr != 0 && size < BDTB_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < BDTB_SIZE_MAX) 
        {
			// priv->ptl->msg.mc_add(priv->ptl, BDTB
			// 			, priv->prd, size, ip, mac);
            unsigned char buf[BDTB_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("bdtb-->size %d msg %s \n",size,buf);
			do_record_data(buf,size,priv);
			return RET_SUCCESS;
		}
	}

	return RET_FAILED;
}
static int do_bdtb_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stBDTBCtrlInfo = {
    .strName        = "BDTB",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_bdtb_action,
    .cbProtoPack    = do_bdtb_pack,
    .private        = NULL
};
