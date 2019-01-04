/*
 * @Author: jiamu 
 * @Date: 2018-10-17 18:12:42 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 18:46:32
 */
#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"


#define M189_POSTFIX	"@189.cn"
#define M189_POSTFIXSIZ	(sizeof(M189_POSTFIX) - 1)
#define M189_ENTRY_NUM	(8)
#define M189_SIZE_MAX	(11)
#define M189_SND_CYCLE	(HZ << 5) /* 32s */
#define M189_BUF_SIZE	(M189_ENTRY_NUM * M189_SIZE_MAX)


static int do_m189_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    if (priv->prd) {
    int			size = 0;
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

  	while (*ptr >= '0' && *ptr <= '9' && size < M189_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size == M189_SIZE_MAX && _is_all_digit(priv->prd, size, M189_SIZE_MAX)) {
			// priv->ptl->msg.mc_add(priv->ptl, M189
			// 			, priv->prd, size, ip, mac);
            unsigned char buf[M189_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("M189-->size:%d info %s \n",size,buf);
            do_record_data(buf,size,priv);
			return RET_SUCCESS;
		}
	}

	return RET_FAILED;
}

PROTOCOL_CONTORL_INFO stM189CtrlInfo = {
    .strName        = "M189",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_m189_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
