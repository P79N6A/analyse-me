/*
 * @Author: jiamu 
 * @Date: 2018-11-14 16:57:15 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-14 16:57:37
 */

#include "protocol.h"
#include "snort_email.h"

static int do_pop_action(int actionType,void *data)
{
    #ifndef TRAFFIC_CMCC
    //m_priv_t *pstPri	= ( m_priv_t *)data;
    printf("Get pop start  data stream \n");
    return do_start_pop(data);
    #endif
    return RET_FAILED;
}

PROTOCOL_CONTORL_INFO stPOPCtrlInfo = {
    .strName        = "SMTP",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_pop_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
