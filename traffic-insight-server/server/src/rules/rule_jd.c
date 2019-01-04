/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:47:04 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 18:08:17
 */
#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"

#define JD_ENTRY_NUM	(8)
#define JD_SIZE_MIN		(5)
#define JD_SIZE_MAX		(32)
#define JD_SND_CYCLE	(HZ << 5) /* 32s */
#define JD_BUF_SIZE		(JD_ENTRY_NUM * JD_SIZE_MAX)

static int do_jd_action(int actionType,void *data)
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
			&& *ptr != '"' && *ptr != '*'
			&& *ptr != 0 && size < JD_SIZE_MAX && ptr < priv->end)
			ptr++, size++;

		if (0 == strncasecmp(priv->prd, "%2A%2A%2A%2A%2A%2A", size)) {
			printpkt("look like user not login, discard this empty account.");
			return -1;
		}

		if (size && size < JD_SIZE_MAX && size > JD_SIZE_MIN) {
            unsigned char buf[JD_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("jd-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			// priv->ptl->msg.mc_add(priv->ptl, JD
			// 			, priv->prd, size, ip, mac);
			return 0;
		}
	}

	return -1;
}



static int do_jd_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stJDCtrlInfo = {
    .strName        = "JD",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_jd_action,
    .cbProtoPack    = do_jd_pack,
    .private        = NULL
};
