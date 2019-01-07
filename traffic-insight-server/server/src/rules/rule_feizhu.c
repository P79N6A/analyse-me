/*
 * @Author: jiamu 
 * @Date: 2019-01-06 20:58:18 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-07 13:58:17
 */

#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"


static int do_feizhu_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    char *strStart  = NULL;
    if (NULL == priv->prd || (strStart = strstr(priv->prd,"cntaobao")) == NULL)
        return RET_FAILED;

    //printf("I get one feizhu %s \n",priv->prd);   
    strStart += strlen("cntaobao");
    char *strEnd = strchr(strStart,'&');
    int size = 0;
    if(strEnd == NULL)
        return RET_FAILED;
    
    unsigned strBuf[256] = {0};
    unsigned strTmp[256] = {0};
    size = strEnd - strStart;
    if(size < 5 || size > sizeof(strBuf))
         return RET_FAILED;
    memcpy(strBuf,strStart,size);

    size = ConvertUrlToAscii(strTmp, sizeof(strTmp), strBuf, strlen(strBuf));
    if(size < 0)
        return RET_FAILED;
    
    //printf("Now get feizhu account %s \n",strTmp);
    do_record_data(strTmp,size,priv);
    
    return RET_SUCCESS;
}
PROTOCOL_CONTORL_INFO stFEIZHUCtrlInfo = {
    .strName        = "FEIZHU",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_feizhu_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};


