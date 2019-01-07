/*
 * @Author: jiamu 
 * @Date: 2018-10-17 19:40:24 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-07 20:40:14
 */
#include "protocol.h"

#define XC_ENTRY_NUM	(4)
#define XC_SIZE_MAX		(64)
#define XC_SND_CYCLE	(HZ << 5) /* 32s */
#define XC_BUF_SIZE		(XC_ENTRY_NUM * XC_SIZE_MAX)

#define XC_FLAG_1 0x3831
#define XC_FLAG_2 0x3631

static int do_xc_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    if (priv->prd) {
		int			size = 0;
		const char	*ptr = priv->prd;
		int idLen = 0;
		unsigned char buf[XC_SIZE_MAX] = {0};
#if 0
		printpkt("patern:%s data:%s\n ht:%x %x %d %d len:%d"
			,((content_match_t *)(priv->r->ds_list[0]))->pattern_buf
			,priv->prd ? priv->prd : "NULL"
			,priv->ht.isrc, priv->ht.idst
			,priv->ht.psrc, priv->ht.pdst
			,priv->skb->len);
#endif
		//printf("I get one xc \n");
		RULE_DETAIL_INFO *pstRuleInfo = (RULE_DETAIL_INFO *)(priv->pstRuleDetail);
		if(pstRuleInfo->ruleNum == 1)
		{
			int find = 0;
			unsigned short ulFlag = 0;
			unsigned char  *strTmp = priv->data + priv->dlen - 8;
			//printf("line = %d \n",__LINE__);
			if( priv->dlen < 30)
			{
				return RET_FAILED;
			}
			//printf("line = %d \n",__LINE__);
			memcpy(&ulFlag,ptr,2);
			//printf("I get one xiecheng ulFlag 0x%04x *strTmp 0x%02x \n",ulFlag,*strTmp);
			if(ulFlag == XC_FLAG_1 && *strTmp == 0x3a)
			{
				strTmp = strstr(priv->data,"\"@");
				if(strTmp == NULL)
				{
					printf("xc wronf data \n");
					return RET_FAILED;
				}
				strTmp - 1;
				find = 1;
			}
			else if(ulFlag == XC_FLAG_2 && *strTmp == 0x32)
			{
				find = 1;
			}
			else
			{
				return RET_FAILED;
			}

			if(find == 0)
			{
				return RET_FAILED;
			}
			size = 0;
			while(strTmp != priv->data && size < 20)
			{
				if(*strTmp == 'M')
				{
					strTmp--;
					break;
				}
				size++,strTmp--;
			}
			idLen =  *strTmp;
			if(idLen != size)
			{
				//printf("Get one wrong data idLen = %02x size = %d \n",idLen,size);
				return RET_FAILED;
			}
			memcpy(buf,strTmp + 1,size);
			printf("I get one xc id %s \n",buf);
			do_record_data(buf,size,priv);

			return RET_SUCCESS;

		}
		else
		{
			skip_space(priv->prd);
			ptr = priv->prd;

			while (*ptr != '"' && *ptr != ' ' && *ptr != ';' && *ptr != '&' && *ptr != '%'
				&& *ptr != ','
				&& *ptr != 0 && size < XC_SIZE_MAX && ptr < priv->end)
				ptr++, size++;
			if (size && size < XC_SIZE_MAX) {
				// priv->ptl->msg.mc_add(priv->ptl, XC
				// 			, priv->prd, size, ip, mac);
				
				memcpy(buf,priv->prd, size);
				printf("xc-->size:%d info:%s \n",size,buf);
				do_record_data(buf,size,priv);
				return 0;
			}
		}
		
	}

	return -1;
}

PROTOCOL_CONTORL_INFO stXCCtrlInfo = {
    .strName        = "XC",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_xc_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
