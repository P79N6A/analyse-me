/*
 * @Author: jiamu 
 * @Date: 2018-10-17 18:00:03 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 18:05:43
 */
#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"

#define MEITUAN_ENTRY_NUM	(32)
#define MEITUAN_SIZE_MAX		(16)
#define MEITUAN_SND_CYCLE	(HZ << 5) /* 32s */
#define MEITUAN_BUF_SIZE		(MEITUAN_ENTRY_NUM * MEITUAN_SIZE_MAX)
#define MEITUAN_NUMLEN_MIN	(5)
#define MEITUAN_NUMLEN_MAX	(11)

static int do_meituan_action(int actionType,void *data)
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

		while (*ptr != '&' && *ptr != ' ' && *ptr != ';' && *ptr != '"'
			&& *ptr != '%' && *ptr != '\n' && *ptr != '\r'
			&& *ptr != 0 && size < MEITUAN_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
		if (size && size < MEITUAN_SIZE_MAX
			&& _is_all_digit(priv->prd, size, MEITUAN_SIZE_MAX)) {
            unsigned char buf[MEITUAN_SIZE_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("meituan-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			// priv->ptl->msg.mc_add(priv->ptl, MEITUAN
			// 			, priv->prd, size, ip, mac);
			return 0;
		}
	}

	return -1;
}
static int do_meituan_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stMEITUANCtrlInfo = {
    .strName        = "MEITUAN",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_meituan_action,
    .cbProtoPack    = do_meituan_pack,
    .private        = NULL
};
