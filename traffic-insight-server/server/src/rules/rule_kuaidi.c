/*
 * @Author: jiamu 
 * @Date: 2018-10-17 18:07:47 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 18:11:45
 */
#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"

#define KUAIDI_ENTRY_NUM	(16)
#define KUAIDI_SIZE_MAX		(16)
#define KUAIDI_SND_CYCLE	(HZ << 5) /* 32s */
#define KUAIDI_BUF_SIZE		(KUAIDI_ENTRY_NUM * KUAIDI_SIZE_MAX)
#define KUAIDI_NUMLEN_MIN	(5)
#define KUAIDI_NUMLEN_MAX	(11)

static int do_kuaidi_action(int actionType,void *data)
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

		while (*ptr != '"' && *ptr != ',' && *ptr != ' ' && *ptr != ';' 
			&& *ptr != '%' && *ptr != '&'
			&& *ptr != 0 && size < KUAIDI_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < KUAIDI_SIZE_MAX
			&& _is_all_digit(priv->prd, size, KUAIDI_SIZE_MAX)) {
            unsigned char buf[KUAIDI_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("kuaidi-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			// priv->ptl->msg.mc_add(priv->ptl, KUAIDI
			// 			, priv->prd, size, ip, mac);
			return 0;
		}
	}

	return -1;
}
static int do_kuaidi_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}

PROTOCOL_CONTORL_INFO stKUAIDICtrlInfo = {
    .strName        = "KUAIDI",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_kuaidi_action,
    .cbProtoPack    = do_kuaidi_pack,
    .private        = NULL
};
