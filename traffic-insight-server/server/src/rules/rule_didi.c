/*
 * @Author: jiamu 
 * @Date: 2018-10-17 15:52:03 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 16:01:37
 */
#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"


#define DIDI_ENTRY_NUM	(32)
#define DIDI_SIZE_MAX		(16)
#define DIDI_SND_CYCLE	(HZ << 5) /* 32s */
#define DIDI_BUF_SIZE		(DIDI_ENTRY_NUM * DIDI_SIZE_MAX)
#define DIDI_NUMLEN_MIN	(5)
#define DIDI_NUMLEN_MAX	(11)


static int do_didi_action(int actionType,void *data)
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

		while (*ptr >=0x30 && *ptr <= 0x39 && size < DIDI_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < DIDI_SIZE_MAX) {
            unsigned char buf[DIDI_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("didi-->size %d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			// priv->ptl->msg.mc_add(priv->ptl, DIDI
			// 			, priv->prd, size, ip, mac);
			return 0;
		}
	}
	return RET_SUCCESS;
}

static int do_didi_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stdidiCtrlInfo = {
    .strName        = "DIDI",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_didi_action,
    .cbProtoPack    = do_didi_pack,
    .private        = NULL
};

