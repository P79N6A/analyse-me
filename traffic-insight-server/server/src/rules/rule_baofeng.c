/*
 * @Author: jiamu 
 * @Date: 2019-01-06 16:46:56 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-06 19:52:54
 */


#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"


#define TH_WEXIN 	"weixin"
#define TH_QQ    	"qq"
#define TH_SINA    	"sina"

static int do_baofeng_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    if (NULL == priv->prd)
        return RET_FAILED;

    int size = 0;
	char *strUid = NULL;
    char *strUserId = NULL;
    const char* ptrData     = priv->prd;
    const char* ptrRowData  = priv->data;
    char strType[16] = {0};
	unsigned char strUidBuf[256] = {0};
	unsigned char strUnBuf[256]  = {0};
	unsigned char strTmp[256] = {0};
	
    RULE_DETAIL_INFO *pstRuleInfo = (RULE_DETAIL_INFO *)(priv->pstRuleDetail);
    if(pstRuleInfo->ruleNum == 1) /*手机号*/
    {
        while (*ptrData != ' ' && *ptrData != ';' && *ptrData != '&' && *ptrData != ',' && *ptrData != '<'
        && *ptrData != 0 && size < 12 && ptrData < priv->end)
        ptrData++, size++;

		if(size != 11)
		{
			return RET_FAILED;
		}
		memcpy(strType,priv->prd,size);
		printf("Now get one baofeng with phone num %s \n",strType);
		do_record_data(strType,size,priv);
    }
    else  if(pstRuleInfo->ruleNum == 2) //qq,wexin,weibo
    {
		//printf("Now get one baofeng with thid %s \n",ptrData);
		strUid = strstr(ptrRowData,"third_uid");
		/*
		*GET /new/thirdparty/authbind?third_uid=3842935625&third_uname=%E5%8D%97%E6%9C%89%E4%B9%94%E6%9C%A8luo&third_type=sina&
		*/
        if(strUid && 
		   (strncasecmp(ptrData,TH_QQ,strlen(TH_QQ)) == 0 || 
		   strncasecmp(ptrData,TH_WEXIN,strlen(TH_WEXIN)) == 0 ||
		   strncasecmp(ptrData,TH_SINA,strlen(TH_SINA)) == 0))
		{
			if(sscanf(strUid,"%*[^=]=%256[^&]&%*[^=]=%256[^&]&%*[^=]=%16[^&]&",strUidBuf,strUnBuf,strType) != 3)
				return RET_FAILED;
			
			printf("type:%s\n",strType);
			printf("uid:%s\n",strUidBuf);
			//printf("name:%s\n",strUnBuf); /*需要URL解码*/

			size = ConvertUrlToAscii(strTmp, sizeof(strTmp), strUnBuf, strlen(strUnBuf));
			//printpkt("uname_num=%d, uname [%s]", size, strTmp);
			printf("name:%s\n",strTmp);

			do_record_data(strUidBuf,strlen(strUidBuf),priv);
			do_record_data(strTmp,size,priv);
		}
        else
        {	
            return RET_FAILED;
        }
    }
	else  if(pstRuleInfo->ruleNum == 3) /*仅仅是获取UID*/
	{
		/*
		*	应该需要获取userid而不是uid
		*/
		#if 0
		GET /logger.php?enc=0&appkey=bfapp_android&ltype=display&log={%22uuid%22:%2200000000-5a0c-9c87-ffff-ffffe7763000%22,
		%22uid%22:%22864590031056331%22,%22imei%22:%22864590031056331%22,%22androidid%22:%22d5ce815443bd6c7e%22,
		%22mac%22:%223c:fa:43:25:aa:ae%22,%22mtype%22:%22HUAWEI%20CAZ-AL10%22,%22gid%22:%22b04%22,
		%22mos%22:%227.0%22,%22ver%22:%227.6.05%22,%22unet%22:%221%22,%22itime%22:%222019-01-06%2018:46:59%22,
		%22userid%22:%22135601920057096375%22,
		%22value%22:%7B%22ui_type%22%3A%2237%22%2C%22section_id%22%3A%2213618%22%2C%22showtime%22%3A%22675%22%2C%22from_pre%22%3A%22jx%22%2C%22screen%22%3A%228%22%2C%22page_id%22%3A%221%22%2C%22request_id%22%3A%22NSBkFvy4NCQui_12002_76%22%2C%22group_id%22%3A%222%22%2C%22is_insert%22%3A%222%22%2C%22ver_switch%22%3A%221%22%2C%22pv_title%22%3A%22jingxuan%22%2C%22order_id%22%3A%2264%22%2C%22from%22%3A%22list%22%2C%22card_type%22%3A%2215%22%2C%22hell%22%3A%2229%22%2C%22aid_set%22%3A%2215525920%22%2C%22card_alginfo%22%3A%22rc-2w2v-1model-2lr10%22%2C%22active_id%22%3A%221546768635622%22%7D} HTTP/1.1
		#endif
		printf("Now get one uid stream \n");
		strUserId = strstr(ptrData,"%22userid%22");
		if(strUserId == NULL)
			return RET_FAILED;
		
		if(sscanf(ptrData,":%256[^,]",strUidBuf) != 1 || strlen(strUidBuf) < 6)
		{
			return RET_FAILED;
		}
		memcpy(strUnBuf,strUidBuf + 3,strlen(strUidBuf) - 6);
		
		printf("Get baofeng uid:%s\n",strUnBuf);
		strUserId += strlen("%22userid%22");
		
		memset(strUnBuf,0,sizeof(strUnBuf));
		memset(strUidBuf,0,sizeof(strUidBuf));

		if(sscanf(strUserId,":%256[^,]",strUidBuf) != 1 || strlen(strUidBuf) < 6)
		{
			return RET_FAILED;
		}
		memcpy(strUnBuf,strUidBuf + 3,strlen(strUidBuf) - 6);
		printf("Get baofeng usrid:%s\n",strUnBuf);

		#if 0
		strUid = strchr(ptrData,'&');
		if(strUid)
		{
			size = strUid - ptrData;
			if(size > 5 && size < 32)
			{
				memcpy(strUidBuf,ptrData,size);
				do_record_data(strUidBuf,strlen(strUidBuf),priv);
				printf("Now get baofeng UID %s \n",strUidBuf);
			}
			else
			{
				return RET_FAILED;
			}
		}
		else
		{
			return RET_FAILED;
		}
		#endif

		return RET_SUCCESS;
	} 
	else
	{
		return RET_FAILED;
	}

  
    /*
    *uid=864590031056331&userid=135601920057096375&token=31F5DE1473C9D2DD822639E946677979
    * 但是有可能为空
    * */
    if((strUid = strstr(ptrRowData,"uid=")) != NULL && (strUserId = strstr(ptrRowData,"&userid=")) != NULL && ((strUserId - ptrRowData) > 10))
    {
        strUid += strlen("uid=");
        size = strUserId - strUid;
        if(size > 5)
        {
            memset(strUidBuf,0,sizeof(strUidBuf));
            memcpy(strUidBuf,strUid,size);
            printf("Now get UID len:%d value:%s \n",size,strUidBuf);
			do_record_data(strUidBuf,strlen(strUidBuf),priv);
            memset(strUnBuf,0,sizeof(strUnBuf));
            strUserId += strlen("&userid=");
            if((strUid = strchr(strUserId,'&')) != NULL && ((size = (strUid - strUserId))) > 5)
            {
                memcpy(strUnBuf,strUserId,size);
                printf("Now get USR len:%d value:%s \n",size,strUnBuf);
				do_record_data(strUserId,strlen(strUserId),priv);
            }
        }
    }

    return RET_SUCCESS;
}
PROTOCOL_CONTORL_INFO stBAOFENGCtrlInfo = {
    .strName        = "BAOFENG",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_baofeng_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};

