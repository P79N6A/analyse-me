/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 18:51:12
 */

#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"

#define MOMO_ENTRY_NUM	(32)
#define MOMO_SIZE_MAX		(16)
#define MOMO_SND_CYCLE	(HZ << 5) /* 32s */
#define MOMO_BUF_SIZE		(MOMO_ENTRY_NUM * MOMO_SIZE_MAX)
#define MOMO_UNDEF_NO  	"1000"
#define MOMO_UNDEF_LEN  	(13)

static int do_momo_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    	if (priv->prd) {
		int 		size = 0;
		const char	*ptr;
   RULE_DETAIL_INFO *r = (RULE_DETAIL_INFO *)(priv->pstRuleDetail);
#if 0
		print("patern:%s data:%s\n ht:%x %x %d %d len:%d"
			,((RULE_CONTENT_MATCH *)(r->ds_list[0]))->pattern_buf
			,priv->prd ? priv->prd : "NULL"
			,priv->ht.saddr, priv->ht.daddr
			,priv->ht.source, priv->ht.dest
			,priv->dlen);
#endif
		skip_space(priv->prd);
		ptr = priv->prd;

		while (*ptr != ' ' && *ptr != '"' && *ptr != '}' && *ptr != '%'
			&& *ptr != 0 && size < MOMO_SIZE_MAX && ptr < priv->end)
			ptr++, size++;

		if (size >= MOMO_UNDEF_LEN && \
			(strncmp((priv->prd), MOMO_UNDEF_NO, strlen(MOMO_UNDEF_NO)) == 0)) {
			printpkt("discard undefine header: %s\n", MOMO_UNDEF_NO);
			return -1;
		}
		if (size && size < MOMO_SIZE_MAX
			&& _is_all_digit(priv->prd, size, MOMO_SIZE_MAX)) {
			// priv->ptl->msg.mc_add(priv->ptl, MOMO
			// 			, priv->prd, size, ip, mac);
            unsigned char buf[MOMO_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("momo-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}

	return -1;
}
PROTOCOL_CONTORL_INFO stMOMOCtrlInfo = {
    .strName        = "MOMO",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_momo_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
