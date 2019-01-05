/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:33:54 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 16:54:07
 */
#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"



#define GANJI_ENTRY_NUM	(8)
#define GANJI_SIZE_MAX		(16)
#define GANJI_SND_CYCLE	(HZ << 5) /* 32s */
#define GANJI_BUF_SIZE		(GANJI_ENTRY_NUM * GANJI_SIZE_MAX)
#define GANJI_NUMLEN_MIN	(5)
#define GANJI_NUMLEN_MAX	(11)


static int do_ganji_action(int actionType,void *data)
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
		printf("r->ruleNum = %d \n",r->ruleNum);
	
		if(r->ruleNum == 1)
		{
			char strUid[32] = {0};
			char strUn[128] = {0};
			char *tmp = strstr(ptr,"&UN=");
			//printf("Now get my new ganji rule:\n%s  \n",ptr);

			if(tmp == NULL || ((size = (tmp - ptr)) > sizeof(strUid)))
			{
				return RET_FAILED;
			}
			memcpy(strUid,ptr,size);
			do_record_data(strUid,size,priv);
			tmp += strlen("&UN=");
			ptr = strstr(tmp,"&TT");

			if(ptr == NULL || ((size = (ptr - tmp)) > sizeof(strUn)))
			{
				return RET_FAILED;
			}
			memcpy(strUn,tmp,size);
			do_record_data(strUn,size,priv);
			return RET_SUCCESS;
		}
		else
		{
			while (*ptr != '&' && *ptr != ' ' && *ptr != '%' && *ptr != 0x0D && *ptr != 0x0A
			&& *ptr != ',' && *ptr != '"' && *ptr != '\'' && *ptr != ';'
			&& *ptr != 0 && size < GANJI_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
			if (size > GANJI_NUMLEN_MIN && size < GANJI_SIZE_MAX
				&& _is_all_digit(priv->prd, size, GANJI_SIZE_MAX)) {
				
				unsigned char buf[GANJI_SIZE_MAX] = {0};
				memcpy(buf,priv->prd, size);
				printf("ganji-->size:%d info:%s \n",size,buf);
				do_record_data(buf,size,priv);
				// priv->ptl->msg.mc_add(priv->ptl, GANJI
				// 			, priv->prd, size, ip, mac);
				return RET_SUCCESS;
			}
		}
		
	}

	return RET_FAILED;
}




static int do_ganji_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stGANJICtrlInfo = {
    .strName        = "GANJI",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_ganji_action,
    .cbProtoPack    = do_ganji_pack,
    .private        = NULL
};

