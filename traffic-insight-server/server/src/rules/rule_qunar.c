/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:12:08
 */

#include "protocol.h"

#define QUNAR_ENTRY_NUM		(4)
#define QUNAR_SIZE_MAX		(32)
#define QUNAR_SND_CYCLE		(HZ << 5) /* 32s */
#define QUNAR_BUF_SIZE		(QUNAR_ENTRY_NUM * QUNAR_SIZE_MAX)
#define QUNAR_VALID_LEN		(9)


static int do_qunar_action(int actionType,void *data)
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

		while (*ptr != '\n' && *ptr != '\r' && *ptr != '"' && *ptr != ';' && *ptr != '%'
			&& *ptr != ' '
			&& *ptr != 0 && size < QUNAR_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < QUNAR_SIZE_MAX && size >= QUNAR_VALID_LEN) {
			// priv->ptl->msg.mc_add(priv->ptl, QUNAR
			// 			, priv->prd, size, ip, mac);

            unsigned char buf[QUNAR_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("QUNAR-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}

	return -1;
}
PROTOCOL_CONTORL_INFO stQUNARCtrlInfo = {
    .strName        = "QUNAR",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_qunar_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
