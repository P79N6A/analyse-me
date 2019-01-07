/*
 * @Author: jiamu 
 * @Date: 2019-01-06 13:12:48 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-06 13:23:20
 */

#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"
/*
*   不是keepalive的数据流
*   会有很频繁的采集动作，考虑是否做限制
*/
static int do_mala_action(int actionType,void *data)
{
     m_priv_t *priv	= data;
     if (priv->prd) 
     {
		int			size = 0;
		const char	*ptr;
        //printf("Now get one mala stream %s \n",priv->prd);
		skip_space(priv->prd);
		ptr = priv->prd;
        
		RULE_DETAIL_INFO *pstRuleInfo = (RULE_DETAIL_INFO *)(priv->pstRuleDetail);
        char strBuf[64] = {0};
        char *tmp = strstr(ptr,"&token");
       	if(tmp == NULL || ((size = (tmp - ptr)) > sizeof(strBuf)))
        {
            return RET_FAILED;
        }
        memcpy(strBuf,ptr,size);
        printf("Now get mala account %s \n",strBuf);
        do_record_data(strBuf,size,priv);
        return RET_SUCCESS;
    }
  
    return RET_FAILED;
}


PROTOCOL_CONTORL_INFO stMALACtrlInfo = {
    .strName        = "MALASHEQU",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_mala_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};

