/*
 * @Author: jiamu 
 * @Date: 2018-10-17 15:25:39 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 15:47:36
 */

#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"

#define DIANPING_ENTRY_NUM	(16)
#define DIANPING_SIZE_MAX		(32)
#define DIANPING_SND_CYCLE	(HZ << 5) /* 32s */
#define DIANPING_BUF_SIZE		(DIANPING_ENTRY_NUM * DIANPING_SIZE_MAX)
#define DIANPING_NUMLEN_MIN	(5)
#define DIANPING_NUMLEN_MAX	(11)

static int do_dianping_action(int actionType,void *data)
{
    m_priv_t *priv	= data;

    	if (priv->prd) {
		int			size = 0;
		const char	*ptr;
        //RULE_DETAIL_INFO *r = (RULE_DETAIL_INFO *)(priv->pstRuleDetail);
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

		while (*ptr != ';' && *ptr != ' ' && *ptr != '"' && *ptr != '&' && *ptr != '?'
			&& *ptr != 0x0d && *ptr != 0x0a
			&& *ptr != 0 && size < DIANPING_SIZE_MAX && ptr < priv->end) {
			if (*ptr == '%') {
				#if 1
				if (((ptr+2) < priv->end) && (*(ptr+1) != '4' || *(ptr+2) != '0')) {
					printpkt("not @ (%c%c)",*(ptr+1),*(ptr+2));
					break;
				} else if ((ptr+2) >= priv->end) {
					printpkt("mail len not enough, size = %d", size);
					size = 0; // set it to invalid size
					break;
				} else {
					printpkt("found mail");
					ptr++, size++;
				}
				#else
				if (((ptr+2) < priv->end) && (*(ptr+1) == '4' || *(ptr+2) == '0')) {
					printpkt("found mail");
					ptr++, size++;
				} else if (((ptr+2) < priv->end) && (*(ptr+1) == '4' || *(ptr+2) == '0')) {
					
				}
				#endif
			} else {
				ptr++, size++;
			}
		}
		if (size && size < DIANPING_SIZE_MAX && size > 3) 
        {
            unsigned char buf[DIANPING_SIZE_MAX] = {0};
            memcpy(buf,priv->prd,size);
            printf("dianping-->size:%d info;%s \n",size,buf);
			do_record_data(buf,size,priv);
			// priv->ptl->msg.mc_add(priv->ptl, DIANPING
			// 			, priv->prd, size, ip, mac);
			return RET_SUCCESS;
		}
	}

	return RET_FAILED;
}



static int do_dianping_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stDIANPINGCtrlInfo = {
    .strName        = "DIANPING",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_dianping_action,
    .cbProtoPack    = do_dianping_pack,
    .private        = NULL
};

