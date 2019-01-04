/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 18:47:19
 */

#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"

#define MILIAO_ENTRY_NUM	(32)
#define MILIAO_SIZE_MAX		(16)
#define MILIAO_SND_CYCLE	(HZ << 5) /* 32s */
#define MILIAO_BUF_SIZE		(MILIAO_ENTRY_NUM * MILIAO_SIZE_MAX)
#define MILIAO_NUMLEN_MIN	(5)
#define MILIAO_NUMLEN_MAX	(11)

static int do_miliao_action(int actionType,void *data)
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

    while (*ptr != '@' && *ptr != ' ' && *ptr != ';' && *ptr != '&'
        && *ptr != 0 && size < MILIAO_SIZE_MAX && ptr < priv->end)
        ptr++, size++;
    if (size && size < MILIAO_SIZE_MAX
        && _is_all_digit(priv->prd, size, MILIAO_SIZE_MAX)) {
        unsigned char buf[MILIAO_SIZE_MAX] = {0};
        memcpy(buf,priv->prd, size);
        printf("miliao-->size:%d info:%s \n",size,buf);
        do_record_data(buf,size,priv);
        // priv->ptl->msg.mc_add(priv->ptl, MILIAO
        //             , priv->prd, size, ip, mac);
        return 0;
        }
    }

	return -1;
}
PROTOCOL_CONTORL_INFO stMILIAOCtrlInfo = {
    .strName        = "MILIAO",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_miliao_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
