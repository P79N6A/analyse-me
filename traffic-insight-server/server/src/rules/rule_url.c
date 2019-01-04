/*
 * @Author: jiamu 
 * @Date: 2018-10-30 19:27:46 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-30 19:39:15
 */
#include "protocol.h"
#include "snort_http.h"

static int do_url_action(int actionType,void *data)
{
    //m_priv_t *pstPri	= ( m_priv_t *)data;
    printf("Get http data stream \n");
    return start_insight_http(data);
}

PROTOCOL_CONTORL_INFO stHttpCtrlInfo = {
    .strName        = "HTTP",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_url_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
