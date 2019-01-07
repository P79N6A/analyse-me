/*
 * @Author: jiamu 
 * @Date: 2019-01-07 10:40:14 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-07 11:29:12
 */


#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"

#define MAX_DOUYU_SIZE 16
static int do_douyu_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    char *ptr  =  priv->prd;
    int  size  = 0;
    char strBuf[MAX_DOUYU_SIZE + 1] = {0};
    RULE_DETAIL_INFO *pstRuleInfo = (RULE_DETAIL_INFO *)(priv->pstRuleDetail);
    if (NULL == ptr)
        return RET_FAILED;

    if(pstRuleInfo->ruleNum == 1)
    {
        /*
        *
        * 没有登陆时是游客身份
        * username@=visitor1735396
        * uid@=0
        * */
        if(sscanf(ptr,"%16[^/]",strBuf) != 1 || strlen(strBuf) < 3)
        {
            return RET_FAILED;
        }
        printf("Now i get one douyu %s\n",strBuf);
        do_record_data(strBuf,strlen(strBuf),priv);
        return RET_SUCCESS;
    }
    else if(pstRuleInfo->ruleNum == 2)
    {
        /*
        *&nlimit=5&u=255306103&ct=android&vid=6357519&
        * */
        if(sscanf(ptr,"%16[^&]",strBuf) != 1 || strlen(strBuf) < 3)
        {
            return RET_FAILED;
        }
        printf("Now i get one douyu with video %s\n",strBuf);
        do_record_data(strBuf,strlen(strBuf),priv);
        return RET_SUCCESS;
    }
    else
    {
        return RET_FAILED;
    }
       

}


PROTOCOL_CONTORL_INFO stDOUYUCtrlInfo = {
    .strName        = "DOUYU",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_douyu_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};

