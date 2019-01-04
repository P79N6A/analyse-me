/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 16:46:08
 */

#include "protocol.h"



PROTOCOL_CONTORL_INFO stHZCtrlInfo = {
    .strName        = "HZ",
    .slMsgNum       = 0,
    .cbProtoHandle  = NULL,
    .cbProtoPack    = NULL,
    .private        = NULL
};
