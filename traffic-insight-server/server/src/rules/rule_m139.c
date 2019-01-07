/*
 * @Author: jiamu 
 * @Date: 2018-10-17 18:12:42 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-06 14:11:41
 */
#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"



#define M139_ENTRY_NUM	(16)
#define M139_SIZE_MAX	(32)
#define M139_SND_CYCLE	(HZ << 5) /* 32s */
#define M139_BUF_SIZE	(M139_ENTRY_NUM * M139_SIZE_MAX)
#define M139_VALID_NUM	(11)


static int do_m139_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    printf("I get one M139 stream \n");
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

    while (*ptr != ' ' && *ptr != ';' && *ptr != '&' && *ptr != ',' && *ptr != '<'
        && *ptr != 0 && size < M139_SIZE_MAX && ptr < priv->end)
        ptr++, size++;
    if (size && size < M139_SIZE_MAX && size == M139_VALID_NUM) {
        unsigned char buf[M139_SIZE_MAX] = {0};
        memcpy(buf,priv->prd, size);
        printf("M139-->size:%d info %s \n",size,buf);
        do_record_data(buf,size,priv);
        // priv->ptl->msg.mc_add(priv->ptl, M139
        //             , priv->prd, size, ip, mac);
        return 0;
    }
	}

	return -1;
}

PROTOCOL_CONTORL_INFO stM139CtrlInfo = {
    .strName        = "M139",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_m139_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
