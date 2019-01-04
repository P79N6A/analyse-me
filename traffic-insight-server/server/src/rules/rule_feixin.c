/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:26:15 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 16:31:58
 */

#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"

#define FEIXIN_PHONE_NUM	(11)
#define FEIXIN_ENTRY_NUM	(8)
#define FEIXIN_SIZE_MAX		(16)
#define FEIXIN_SND_CYCLE	(HZ << 5) /* 32s */
#define FEIXIN_BUF_SIZE		(FEIXIN_ENTRY_NUM * FEIXIN_SIZE_MAX)




static int do_feixin_action(int actionType,void *data)
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

		while (*ptr != '&' && *ptr != '"' && *ptr != '>' && *ptr != '\\' 
			&&*ptr != ';' &&*ptr != ' ' 
			&& *ptr != 0 && size < FEIXIN_SIZE_MAX && ptr < priv->end)
			ptr++, size++;

#if 1
		if (size == FEIXIN_PHONE_NUM && strnstr(priv->prd, "13800138000", FEIXIN_PHONE_NUM)) {
			printpkt("feixin: discard msg center NO. 13800138000");
			return RET_FAILED;
		}
#endif

		if (size && size < FEIXIN_SIZE_MAX
			&& _is_all_digit(priv->prd, size, FEIXIN_SIZE_MAX)) 
        {
            unsigned char buf[FEIXIN_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("feixin-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			// priv->ptl->msg.mc_add(priv->ptl, FEIXIN
			// 			, priv->prd, size, ip, mac);
			return RET_SUCCESS;
		}
	}

	return RET_FAILED;
}





static int do_feixin_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stFEIXINCtrlInfo = {
    .strName        = "FEIXIN",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_feixin_action,
    .cbProtoPack    = do_feixin_pack,
    .private        = NULL
};

