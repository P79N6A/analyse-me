/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-06 13:34:02
 */

#include "protocol.h"


#define WY163_POSTFIX		"@163.com"
#define WY126_POSTFIX		"@126.com"
#define WY163_POSTFIXSIZ	(sizeof(WY163_POSTFIX) - 1)
#define WY126_POSTFIXSIZ	(sizeof(WY126_POSTFIX) - 1)
#define WY163_ENCODE_POSTFIX		"%40163.com"
#define WY126_ENCODE_POSTFIX		"%40126.com"
#define WY163_ENCODE_POSTFIXSIZ	(sizeof(WY163_ENCODE_POSTFIX) - 1)
#define WY126_ENCODE_POSTFIXSIZ	(sizeof(WY126_ENCODE_POSTFIX) - 1)

#define WY163_ENTRY_NUM		(8)
#define WY163_SIZE_MAX		(64 - WY163_ENCODE_POSTFIXSIZ)
#define WY163_SND_CYCLE		(HZ << 5) /* 32s */
#define WY163_BUF_SIZE		(WY163_ENTRY_NUM * WY163_SIZE_MAX)

static int do_wy163_action(int actionType,void *data)
{
    m_priv_t *priv	= ( m_priv_t *)data;
    unsigned char buf[WY126_POSTFIXSIZ + WY163_SIZE_MAX * 2] = {0};

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

		while (*ptr != ';' && *ptr != '@' && *ptr != '\r' && *ptr != '\n' && *ptr != ' '
			&& *ptr != '"' && *ptr != ',' && *ptr != '|' && *ptr != '%'
			&& *ptr != 0 && size < WY163_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < WY163_SIZE_MAX 
			&& (!memcmp(ptr, WY163_POSTFIX, WY163_POSTFIXSIZ)
				|| !memcmp(ptr, WY126_POSTFIX, WY126_POSTFIXSIZ))) {
			// priv->ptl->msg.mc_add(priv->ptl, WY163
			// 			, priv->prd, size + WY163_POSTFIXSIZ, ip, mac);
            memcpy(buf,priv->prd, size + WY163_POSTFIXSIZ);
            printf("WY163-->size:%d info:%s \n",size + WY163_POSTFIXSIZ,buf);
			do_record_data(buf,size + WY163_POSTFIXSIZ,priv);
			return 0;
		} else if (size && size < WY163_SIZE_MAX 
			&& (!memcmp(ptr, WY163_ENCODE_POSTFIX, WY163_ENCODE_POSTFIXSIZ)
				|| !memcmp(ptr, WY126_ENCODE_POSTFIX, WY126_ENCODE_POSTFIXSIZ))) {
			char		mail[64];

			memset(mail, 0, sizeof(mail));
			strncpy(mail, priv->prd, size);
			if (!memcmp(ptr, WY126_ENCODE_POSTFIX, WY126_ENCODE_POSTFIXSIZ))
				strncpy(mail+size, WY126_POSTFIX, strlen(WY126_POSTFIX));
			else
				strncpy(mail+size, WY163_POSTFIX, strlen(WY163_POSTFIX));

			printpkt("get mail=[%s]",mail);
			// priv->ptl->msg.mc_add(priv->ptl, WY163
			// 			, mail, size + WY163_ENCODE_POSTFIXSIZ, ip, mac);
            
            memcpy(buf,priv->prd, size + WY163_ENCODE_POSTFIXSIZ);
            printf("WY163-->size:%d info:%s \n",size + WY163_ENCODE_POSTFIXSIZ,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}

	return -1;
}

PROTOCOL_CONTORL_INFO stWY163CtrlInfo = {
    .strName        = "WY163",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_wy163_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
