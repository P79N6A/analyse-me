/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:07:44
 */

#include "protocol.h"

#define QQM_POSTFIX		"@qq.com"
#define QQM_POSTFIXSIZ	(sizeof(QQM_POSTFIX) - 1)
#define QQM_ENTRY_NUM	(16)
#define QQM_SIZE_MAX	(32 - QQM_POSTFIXSIZ)
#define QQM_SND_CYCLE	(HZ << 5) /* 32s */
#define QQM_BUF_SIZE	(QQM_ENTRY_NUM * QQM_SIZE_MAX)

static int do_qqm_action(int actionType,void *data)
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

    while (*ptr != '@' && *ptr != '%' && *ptr != '\r' && *ptr != '\n'
        && *ptr != '&' && *ptr != ';'
        && *ptr != 0 && size < QQM_SIZE_MAX && ptr < priv->end)
        ptr++, size++;
    if (size && size < QQM_SIZE_MAX
        && _is_all_digit(priv->prd, size, QQM_SIZE_MAX)) {
        // priv->ptl->msg.mc_add(priv->ptl, QQM
        //             , priv->prd, size, ip, mac);
        unsigned char buf[QQM_SIZE_MAX] = {0};
        memcpy(buf,priv->prd, size);
        printf("QQM-->size:%d info:%s \n",size,buf);
        do_record_data(buf,size,priv);
        return 0;
    }
}
     return 0;
}

PROTOCOL_CONTORL_INFO stQQMCtrlInfo = {
    .strName        = "QQM",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_qqm_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
