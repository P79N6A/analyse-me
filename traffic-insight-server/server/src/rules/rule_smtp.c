/*
 * @Author: jiamu 
 * @Date: 2018-11-07 11:56:05 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-07 13:38:11
 */

#include "protocol.h"
#include "snort_email.h"

static int do_smtp_action(int actionType,void *data)
{
    //m_priv_t *pstPri	= ( m_priv_t *)data;
    printf("Get smtp start  data stream \n");
     return do_start_smtp(data);
}

PROTOCOL_CONTORL_INFO stSMTPCtrlInfo = {
    .strName        = "SMTP",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_smtp_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
