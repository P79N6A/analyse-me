/*
 * @Author: jiamu 
 * @Date: 2019-01-07 16:31:31 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-07 17:02:57
 */

#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"


static int do_meipai_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    char *ptr  =  priv->prd;
    int  size  = 0;
    char strBuf[32] = {0};
    RULE_DETAIL_INFO *pstRuleInfo = (RULE_DETAIL_INFO *)(priv->pstRuleDetail);
    if (NULL == ptr)
        return RET_FAILED;

    skip_space(priv->prd);
	ptr = priv->prd;
    
    if(pstRuleInfo->ruleNum == 1)
    {
        
        char *strEnd = strchr(ptr,'&');
        if(strEnd == NULL )
        {
            return RET_FAILED;
        }
        size = strEnd -  ptr;
        if(size < 3 || size > 16)
        {
            return RET_FAILED;
        }
        memcpy(strBuf,ptr,size);

        if(!_is_all_digit(strBuf, size, 16))
        {
            return RET_FAILED;
        }

        printf("I get one meipai %s\n",strBuf);
        do_record_data(strBuf,size,priv);
        
        return RET_SUCCESS;
    }
    else
    {
        return RET_FAILED;
    }
}

PROTOCOL_CONTORL_INFO stMEIPAICtrlInfo = {
    .strName        = "MEIPAI",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_meipai_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};

