/*
 * @Author: jiamu 
 * @Date: 2018-10-17 15:08:29 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 15:17:50
 */

#include "protocol.h"


#define ALIWX_ENTRY_NUM		(16)
#define ALIWX_SIZE_MAX		(64)
#define ALIWX_SND_CYCLE		(HZ << 5) /* 32s */
#define ALIWX_BUF_SIZE		(ALIWX_ENTRY_NUM * ALIWX_SIZE_MAX)


static int do_aliwx_action(int actionType,void *data)
{
    m_priv_t *priv	= data;

	if (priv->prd) 
    {
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

		while (*ptr != ';' && *ptr != '&' && *ptr != 0	&& size < ALIWX_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < ALIWX_SIZE_MAX) {
            unsigned char buf[ALIWX_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("aliwx-->size %d msg %s \n",size,buf);
			do_record_data(buf,size,priv);
			// priv->ptl->msg.mc_add(priv->ptl, ALIWX
			// 			, priv->prd, size, ip, mac);
			return 0;
		}
	}
	return 0;
}




static int do_aliwx_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stALIWXCtrlInfo = {
    .strName        = "ALIWX",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_aliwx_action,
    .cbProtoPack    = do_aliwx_pack,
    .private        = NULL
};