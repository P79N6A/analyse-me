/*
 * @Author: jiamu 
 * @Date: 2018-10-17 19:21:59 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:27:47
 */

#include "protocol.h"

#define TMALL_ENTRY_NUM		(16)
#define TMALL_SIZE_MAX			(128)
#define TMALL_REAL_SIZE_MAX	(64)
#define TMALL_BUF_SIZE			(TMALL_ENTRY_NUM * TMALL_SIZE_MAX)
#define TMALL_MIN_VALID_CHAR	0x30
#define TMALL_SND_CYCLE		(HZ << 5) /* 32s */
#define TMALL_UNICODE_CHAR	"%5Cu"


static int do_tmall_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    if (priv->prd) {
		int			size = 0;
		int			is_uni = 0;
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


		while (*ptr != '@' && *ptr != ' ' && *ptr != ';' && *ptr != '&' 
			&& *ptr != 0 && size < TMALL_SIZE_MAX && ptr < priv->end) {
			if (*ptr != '%' && ((*ptr & 0xFF) < TMALL_MIN_VALID_CHAR)) {
				printpkt("found other char, break , c = %#x\n", *ptr);
				break;
			}
			if (0 == strncmp(ptr, TMALL_UNICODE_CHAR, strlen(TMALL_UNICODE_CHAR))) {
				is_uni++;
			}
			ptr++, size++;
		}
		if (size && size < TMALL_SIZE_MAX && size > 3) {
			char uname[TMALL_SIZE_MAX+1];
			int uname_num = 0;

			if (!is_uni) {
				uname_num = ConvertUrlToAscii(uname, TMALL_SIZE_MAX, priv->prd, size);
				printpkt("uname_num=%d, uname [%s]", uname_num, uname);
			} else {
				uname_num = ConvertNativeToAscii(uname, TMALL_SIZE_MAX, priv->prd, size);
				printpkt("unicode uname_num=%d, uname [%s]", uname_num, uname);
			}

			if (uname_num > 0 && uname_num < TMALL_REAL_SIZE_MAX) {
				// priv->ptl->msg.mc_add(priv->ptl, TMALL
				// 			, uname, uname_num, ip, mac);

                unsigned char buf[TMALL_REAL_SIZE_MAX] = {0};
                memcpy(buf,uname, uname_num);
                printf("tmall-->size:%d info:%s \n",uname_num,buf);
				do_record_data(buf,uname_num,priv);
				return 0;
			}
		}
	}

	return -1;
}

PROTOCOL_CONTORL_INFO stTMALLCtrlInfo = {
    .strName        = "TMALL",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_tmall_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
