/*
 * @Author: jiamu 
 * @Date: 2018-11-12 20:10:41 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-12 20:14:14
 */


#include "protocol.h"
#include "snort_email.h"

static int do_imap4_action(int actionType,void *data)
{
    //m_priv_t *pstPri	= ( m_priv_t *)data;
    printf("Get imap start  data stream \n");
     return do_start_imap(data);
}

PROTOCOL_CONTORL_INFO stIMAP4CtrlInfo = {
    .strName        = "IMAP4",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_imap4_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
