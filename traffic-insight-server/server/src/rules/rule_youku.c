/*
 * @Author: jiamu 
 * @Date: 2019-01-07 12:52:16 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-07 13:26:24
 */


#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"

#define MAX_ID_LEN 32

static int do_youku_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    
   
    if (NULL == priv->prd)
        return RET_FAILED;
    //printf("I get one youku stream %s \n",priv->prd);
    RULE_DETAIL_INFO *pstRuleInfo = (RULE_DETAIL_INFO *)(priv->pstRuleDetail);
    skip_space(priv->prd);
    char *ptr = priv->prd;
    char strBuf[32] = {0};
    int size = 0;

    if(pstRuleInfo->ruleNum == 1)
    {
        /*
        *#d?appid=1001&ytid=1370040961&platform=2&ver=7.5.9&utdid
        */
        while(*ptr >= '0' && *ptr <= '9' 
            && *ptr != 0 && size < MAX_ID_LEN && ptr < priv->end)
        {
            ptr++, size++;
        }
        memcpy(strBuf,priv->prd,size);    
    }
    else
    {
        return RET_FAILED;
    }

    //size = strlen(strBuf);
    if(size > 3 && size < MAX_ID_LEN)
    {
        if(!_is_all_digit(strBuf, size, MAX_ID_LEN))
        {
            return RET_FAILED;
        }

        printf("I get youku id %s\n",strBuf);
        do_record_data(strBuf,size,priv);
        return  RET_SUCCESS;
    }
    else
    {
        return RET_FAILED;
    }
    return RET_FAILED;
}
PROTOCOL_CONTORL_INFO stYOUKUCtrlInfo = {
    .strName        = "YOUKU",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_youku_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};

