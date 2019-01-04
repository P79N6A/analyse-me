/*
 * @Author: jiamu 
 * @Date: 2018-09-27 13:56:33 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-09-27 14:17:37
 */


#include "im_config.h"



static const IM_ERRCODE_DESCR stErrcodeRorde[] = 
{
    {RET_SUCCESS,"Success"},
    {RET_FAILED, "Unknown erro"}
};

const char * im_strerror(int eErrCode)
{
    int i = 0;

    for(i = 0;i < (sizeof(stErrcodeRorde)/sizeof(stErrcodeRorde[0]));i++)
    {
        if(stErrcodeRorde[i].eErrCode == eErrCode)
        {
            return stErrcodeRorde[i].strErrDescr;
        }
    }
    return NULL;
}


