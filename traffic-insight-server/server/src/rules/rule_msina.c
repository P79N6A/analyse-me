/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:03:51
 */

#include "protocol.h"

#define MSINA_ENTRY_NUM	(8)
#define MSINA_SIZE_MAX	(32)
#define MSINA_SND_CYCLE	(HZ << 5) /* 32s */
#define MSINA_BUF_SIZE	(MSINA_ENTRY_NUM * MSINA_SIZE_MAX)

static int do_msina_action(int actionType,void *data)
{
    m_priv_t *priv	= data;

    	if (priv->prd) {
		int			size = 0;
		int			have_at = 0;
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
			&& *ptr != 0 && size < MSINA_SIZE_MAX && ptr < priv->end) {
			if (*ptr == '@') {
				have_at++;
			} else if (*ptr == '%') {
				if (((ptr+3+8) < priv->end) && *(ptr+1) == '4' && *(ptr+2) == '0') {
					have_at++;
				} else if (((ptr+2) < priv->end) && *(ptr+1) == '2' && *(ptr+2) == '2') {
					break;
				} else {
					printpkt("sinamail: invalid mail format(%c%c%c, last %d)",
						*ptr,*(ptr+1),*(ptr+2), priv->end-ptr);
					size = 0;
					break;
				}
			}
			ptr++, size++;
		}

		if (have_at != 1) {
			printpkt("sinamail: '@' count not 1 (%d)",have_at);
			return -1;
		}
		
		if (size && size < MSINA_SIZE_MAX) {
			// priv->ptl->msg.mc_add(priv->ptl, MSINA
			// 			, priv->prd, size, ip, mac);
            unsigned char buf[MSINA_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("MSINA-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}

	return -1;

}
PROTOCOL_CONTORL_INFO stMSINACtrlInfo = {
    .strName        = "MSINA",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_msina_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
