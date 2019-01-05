/*
 * @Author: jiamu 
 * @Date: 2018-10-19 16:07:54 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-19 16:08:52
 */
#include "record_db.h"
#include "record_data.h"
#include "log.h"
#include "snort_http.h"
#include "snort_email.h"

#ifndef TRAFFIC_CMCC

#include <sqlite3.h>
#define DATA_BASE_NAME "/etc/traffic-insight/traffic-insight.db"

#define CREATE_TERM_RECORD_CMD  "create table record(id integer primary key,\
	mac   text not null collate nocase, \
	ip    text not null collate nocase, \
	num   integer, \
	type  text not null collate nocase, \
	value text not null collate nocase, \
	online TIMESTAMP not null, \
	active NOT NULL DEFAULT (datetime('now','localtime')));"


#define CREATE_HTTPLOG_RECORD_CMD  "create table httplog(id integer primary key,\
	mac   text not null collate nocase, \
	ip    text not null collate nocase, \
	value text not null collate nocase,\
	online NOT NULL DEFAULT (datetime('now','localtime')));"

#define CREATE_EMAIL_RECORD_CMD  "create table email(id integer primary key,\
	mac   text not null collate nocase,\
	ip    text not null collate nocase,\
	user  text collate nocase,\
	key   text collate nocase,\
	type  text not null collate nocase,\
	emailfrom  	 text collate nocase,\
	emailto   text collate nocase,\
	subject  text collate nocase,\
	content  text collate nocase,\
	attach   text collate nocase,\
	online NOT NULL DEFAULT (datetime('now','localtime')));"

#define CONDITION_IN_TODAY  "date(online) = date('now')"

#define SELECT_TERM_BY_MAC_TYPE_TODAY(findmac,findtype,buf) \
do{\
	snprintf(buf,sizeof(buf)/sizeof(buf[0]),"select * from record " \
		"where mac='%02x:%02x:%02x:%02x:%02x:%02x' " \
		"type=%s "\
		"date(online) = date('now')" ,\
		findmac[0],findmac[1],findmac[2],findmac[3],findmac[4],findmac[5],\
		findtype);\
}while(0)


typedef sqlite3 * DbHandle;
typedef sqlite3_stmt * DbResultStmt;
#define MAX_SQL_QUERY_LEN 1024

/*sqlite3相关的API*/
#define SAFE_DB_OPEN_V2(path,handle,flag) \
if( ((sqlite3_open_v2(path, &(handle),(flag), NULL)) != SQLITE_OK )) {printf("traffic-insight open database failed, errmsg : %s", sqlite3_errmsg(handle));return -1;}

#define SAFE_DB_OPEN(path,handle) \
if( ((sqlite3_open(path, &(handle))) != SQLITE_OK ) ){printf("traffic-insight open database failed, errmsg : %s", sqlite3_errmsg(handle));return -1;}

#define SAFE_DB_TIMEOUT(handle, timeout)\
if( ((sqlite3_busy_timeout(handle, timeout)) != SQLITE_OK)){printf("traffic-insight set database timeout failed, errmsg : %s", sqlite3_errmsg(handle));return -1;}

#define SAFE_DB_EXEC(handle,sql)\
if( ( (sqlite3_exec(handle,sql,NULL,NULL,NULL)) != SQLITE_OK ) ){printf("traffic-insight exec database sql query failed, errmsg : %s", sqlite3_errmsg(handle));sqlite3_close(handle);return -1;}

#define SAFE_DB_PREPARE_V2(handle, sql, sql_len, result) \
if( ( (sqlite3_prepare_v2(handle,sql,sql_len,&(result),NULL)) != SQLITE_OK ) ){printf("traffic-insight exec database sql query failed, errmsg : %s", sqlite3_errmsg(handle));sqlite3_finalize(result);sqlite3_close(handle);return -1;}	

#define SAFE_DB_CLOSE(handle)\
if( ( (sqlite3_close(handle) != SQLITE_OK )) ){printf("traffic-insight close database failed, errmsg : %s", sqlite3_errmsg(handle));return -1;}




/**
 * @brief 
 *  删除时间在一个月以上的记录
 *  比如现在是10月
 *  删除从8/1到8/31的记录
 *  日期是自动推导的
 * @return int 
 */

int do_delete_overtime_term(void)
{
    DbHandle db=NULL;

    INFO("delete terminals over 1 months");

    SAFE_DB_OPEN_V2(DATA_BASE_NAME, db, SQLITE_OPEN_READWRITE);
	SAFE_DB_TIMEOUT(db, 1000);
    #if 0
    SAFE_DB_EXEC(db, "delete from record "
	"where date(online) " 
	"between "
	"date('now','start of month','-2 month')  "
	"and " 
	"date('now','start of month','-1 month','-1 day');");

    SAFE_DB_EXEC(db, "delete from httplog "
	"where date(online) " 
	"between "
	"date('now','start of month','-2 month')  "
	"and " 
	"date('now','start of month','-1 month','-1 day');");

    SAFE_DB_EXEC(db, "delete from email "
	"where date(online) " 
	"between "
	"date('now','start of month','-2 month')  "
	"and " 
	"date('now','start of month','-1 month','-1 day');");
    #else
    SAFE_DB_EXEC(db, "delete from record "
	"where date(online) < date('now','start of month','-1 month') ; " );
	
     SAFE_DB_EXEC(db, "delete from httplog "
	"where date(online) < date('now','start of month','-1 month') ; " );

    SAFE_DB_EXEC(db, "delete from email "
	"where date(online) < date('now','start of month','-1 month') ; " );
    #endif

    SAFE_DB_CLOSE(db);
	INFO("traffic-insight database flush the terminals over 1 months successful");
    return RET_SUCCESS;
}
/**
 * @brief 
 * 插入一个新的设备
 * @param term 
 * @param account 
 * @return int 
 */
int do_insert_newone(const void *term,void *account)
{
    DbHandle db=NULL;
	//DbResultStmt result = NULL;
	char queryApConfSql[MAX_SQL_QUERY_LEN] = {0};
    const TERM_RECORD_INFO   *pstTerminal    = (const TERM_RECORD_INFO *)term;
    const ACCOUNT_TYPE_INFO  *pstAccountInfo = (const ACCOUNT_TYPE_INFO *)account;
    unsigned int ulIp = htonl(pstTerminal->ulIPAddr);

    char timestamp[128] = {0};
	strftime(timestamp,128,"%Y-%m-%d %H:%M:%S",localtime(&pstTerminal->stTimeStamp));

    snprintf(queryApConfSql,MAX_SQL_QUERY_LEN,
    "insert into "
    "record(mac,ip,num,type,value,online,active) "
    "values('%02x:%02x:%02x:%02x:%02x:%02x','%s',1,'%s','%s','%s','%s');",
    pstTerminal->ucMacAddr[0],pstTerminal->ucMacAddr[1],pstTerminal->ucMacAddr[2],
    pstTerminal->ucMacAddr[3],pstTerminal->ucMacAddr[4],pstTerminal->ucMacAddr[5],
    int_ntoa (ulIp),pstAccountInfo->strType,pstAccountInfo->value,timestamp,timestamp);

    INFO("%s",queryApConfSql);
    SAFE_DB_OPEN_V2(DATA_BASE_NAME, db, SQLITE_OPEN_READWRITE);
	SAFE_DB_TIMEOUT(db, 1000);

    SAFE_DB_EXEC(db,queryApConfSql);

    SAFE_DB_CLOSE(db);
    return RET_SUCCESS;
}
/**
 * @brief 
 * 均select *
 * 只是可能条件不同
 * 1.先查询个数
 * @param strCmd 
 * @return int 
 */
int do_find_terminal(char *strCmd,int *pslEntryNum,DATABASE_RECORD_ENTRY **ppentry)
{
    int index = 0;
    int slEntryNum = 0,slEntryIndex = 0;
    const unsigned char *str = NULL;
    DbHandle db = NULL;
    DbResultStmt result = NULL;
    DATABASE_RECORD_ENTRY    *pstDbEntry = NULL;
    char strFindTermSql[MAX_SQL_QUERY_LEN] = {0};
    char *strFind = strstr(strCmd,"from");
    if(strFind == NULL)
    {
        return RET_FAILED;
    }
    snprintf(strFindTermSql,MAX_SQL_QUERY_LEN,"select count() %s",strFind);

    SAFE_DB_OPEN_V2(DATA_BASE_NAME, db, SQLITE_OPEN_READONLY);
	SAFE_DB_TIMEOUT(db, 1000);

    SAFE_DB_PREPARE_V2(db, strFindTermSql, strlen(strFindTermSql), result);
    if (sqlite3_step(result) != SQLITE_ROW)
    {
        goto err;
    }
    slEntryNum = sqlite3_column_int(result, index);
    print("slEntryNum = %d \n",slEntryNum);
    sqlite3_finalize(result);
    if(slEntryNum == 0)
    {
        goto err;
    }
    pstDbEntry = calloc(slEntryNum,sizeof(DATABASE_RECORD_ENTRY));
    if(NULL == pstDbEntry)
    {
        goto err;
    }
    memset(pstDbEntry,0,sizeof(DATABASE_RECORD_ENTRY) * slEntryNum);

    /*开始按照真正的规则查找*/
    result = NULL;
    SAFE_DB_PREPARE_V2(db, strCmd, strlen(strCmd), result);
    while (sqlite3_step(result) == SQLITE_ROW && slEntryIndex < slEntryNum)
    {   
        index = 0;
        pstDbEntry[slEntryIndex].slId = sqlite3_column_int(result, index++);

        str = sqlite3_column_text(result, index++);
		if(str)
			snprintf(pstDbEntry[slEntryIndex].strMac, sizeof(pstDbEntry[slEntryIndex].strMac), "%s", str);
        
        str = sqlite3_column_text(result, index++);
		if(str)
			snprintf(pstDbEntry[slEntryIndex].strIp, sizeof(pstDbEntry[slEntryIndex].strIp), "%s", str);

        pstDbEntry[slEntryIndex].slAcountNum = sqlite3_column_int(result, index++);

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strAccountType, sizeof(pstDbEntry[slEntryIndex].strAccountType), "%s", str);

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strAccountVal, sizeof(pstDbEntry[slEntryIndex].strAccountVal), "%s", str);
        

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strOnlineTime, sizeof(pstDbEntry[slEntryIndex].strOnlineTime), "%s", str);

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strActiveTime, sizeof(pstDbEntry[slEntryIndex].strActiveTime), "%s", str);
		
        slEntryIndex++;
    }  
	sqlite3_finalize(result);

    if(slEntryIndex != slEntryNum)
    {
        INFO("Now select count() is %d ,but get %d ",slEntryNum,slEntryIndex);
    }
    else
    {
        goto err;
    }

    if(NULL != pstDbEntry)
    {
        free(pstDbEntry);
        pstDbEntry = NULL;
    }
err:
    SAFE_DB_CLOSE(db);
	*pslEntryNum = slEntryIndex;
	*ppentry = pstDbEntry;
    return pstDbEntry == NULL ? RET_FAILED : RET_SUCCESS;

}

int do_find_url(char *strCmd,int *pslEntryNum,HTTP_DB_ENTRY **ppentry)
{
    int index = 0;
    int slEntryNum = 0,slEntryIndex = 0;
    const unsigned char *str = NULL;
    DbHandle db = NULL;
    DbResultStmt result = NULL;
    int maxEntryNum    =  (60 * 1024) / sizeof(HTTP_DB_ENTRY); /*ubus通信建议不超过64k*/
    HTTP_DB_ENTRY    *pstDbEntry = NULL;
    char strFindTermSql[MAX_SQL_QUERY_LEN] = {0};
    char *strFind = strstr(strCmd,"from");
    if(strFind == NULL)
    {
        return RET_FAILED;
    }
    snprintf(strFindTermSql,MAX_SQL_QUERY_LEN,"select count() %s",strFind);

    SAFE_DB_OPEN_V2(DATA_BASE_NAME, db, SQLITE_OPEN_READONLY);
	SAFE_DB_TIMEOUT(db, 1000);

    SAFE_DB_PREPARE_V2(db, strFindTermSql, strlen(strFindTermSql), result);
    if (sqlite3_step(result) != SQLITE_ROW)
    {
        goto err;
    }
    slEntryNum = sqlite3_column_int(result, index);
    print("slEntryNum = %d \n",slEntryNum);
    sqlite3_finalize(result);
    if(slEntryNum == 0)
    {
        goto err;
    }
    pstDbEntry = calloc(slEntryNum,sizeof(HTTP_DB_ENTRY));
    if(NULL == pstDbEntry)
    {
        goto err;
    }
    if(maxEntryNum < slEntryNum)
    {
        slEntryNum = maxEntryNum;
    }
    memset(pstDbEntry,0,sizeof(HTTP_DB_ENTRY) * slEntryNum);

    /*开始按照真正的规则查找*/
    result = NULL;
    SAFE_DB_PREPARE_V2(db, strCmd, strlen(strCmd), result);
    while (sqlite3_step(result) == SQLITE_ROW && slEntryIndex < slEntryNum)
    {   
        index = 0;
        pstDbEntry[slEntryIndex].slId = sqlite3_column_int(result, index++);

        str = sqlite3_column_text(result, index++);
		if(str)
			snprintf(pstDbEntry[slEntryIndex].strMac, sizeof(pstDbEntry[slEntryIndex].strMac), "%s", str);
        
        str = sqlite3_column_text(result, index++);
		if(str)
			snprintf(pstDbEntry[slEntryIndex].strIp, sizeof(pstDbEntry[slEntryIndex].strIp), "%s", str);

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strUrl, sizeof(pstDbEntry[slEntryIndex].strUrl), "%s", str);
        

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strOnlineTime, sizeof(pstDbEntry[slEntryIndex].strOnlineTime), "%s", str);
		
        slEntryIndex++;
    }  
	sqlite3_finalize(result);

    if(slEntryIndex != slEntryNum)
    {
        INFO("Now select count() is %d ,but get %d ",slEntryNum,slEntryIndex);
    }
    else
    {
        goto err;
    }

    if(NULL != pstDbEntry)
    {
        free(pstDbEntry);
        pstDbEntry = NULL;
    }
err:
    SAFE_DB_CLOSE(db);
	*pslEntryNum = slEntryIndex;
	*ppentry = pstDbEntry;
    return pstDbEntry == NULL ? RET_FAILED : RET_SUCCESS;

}

int do_find_email(char *strCmd,int *pslEntryNum,EMAIL_DB_ENTRY **ppentry)
{
    int index = 0;
    int slEntryNum = 0,slEntryIndex = 0;
    const unsigned char *str = NULL;
    DbHandle db = NULL;
    DbResultStmt result = NULL;
    int maxEntryNum    =  (60 * 1024) / sizeof(EMAIL_DB_ENTRY); /*ubus通信建议不超过64k*/
    EMAIL_DB_ENTRY    *pstDbEntry = NULL;
    char strFindTermSql[MAX_SQL_QUERY_LEN] = {0};
    char *strFind = strstr(strCmd,"from");
    if(strFind == NULL)
    {
        return RET_FAILED;
    }
    snprintf(strFindTermSql,MAX_SQL_QUERY_LEN,"select count() %s",strFind);

    SAFE_DB_OPEN_V2(DATA_BASE_NAME, db, SQLITE_OPEN_READONLY);
	SAFE_DB_TIMEOUT(db, 1000);

    SAFE_DB_PREPARE_V2(db, strFindTermSql, strlen(strFindTermSql), result);
    if (sqlite3_step(result) != SQLITE_ROW)
    {
        goto err;
    }
    slEntryNum = sqlite3_column_int(result, index);
    print("slEntryNum = %d \n",slEntryNum);
    sqlite3_finalize(result);
    if(slEntryNum == 0)
    {
        goto err;
    }
    if(maxEntryNum < slEntryNum)
    {
        slEntryNum = maxEntryNum;
    }
    pstDbEntry = calloc(slEntryNum,sizeof(EMAIL_DB_ENTRY));
    if(NULL == pstDbEntry)
    {
        goto err;
    }
    memset(pstDbEntry,0,sizeof(EMAIL_DB_ENTRY) * slEntryNum);

    /*开始按照真正的规则查找*/
    result = NULL;
    SAFE_DB_PREPARE_V2(db, strCmd, strlen(strCmd), result);
    while (sqlite3_step(result) == SQLITE_ROW && slEntryIndex < slEntryNum)
    {   
        index = 0;
        pstDbEntry[slEntryIndex].slId = sqlite3_column_int(result, index++);

        str = sqlite3_column_text(result, index++);
		if(str)
			snprintf(pstDbEntry[slEntryIndex].strMac, sizeof(pstDbEntry[slEntryIndex].strMac), "%s", str);
        
        str = sqlite3_column_text(result, index++);
		if(str)
			snprintf(pstDbEntry[slEntryIndex].strIp, sizeof(pstDbEntry[slEntryIndex].strIp), "%s", str);

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strUser, sizeof(pstDbEntry[slEntryIndex].strUser), "%s", str);
        

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strKey, sizeof(pstDbEntry[slEntryIndex].strKey), "%s", str);
		
        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strDir, sizeof(pstDbEntry[slEntryIndex].strDir), "%s", str);

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strFrom, sizeof(pstDbEntry[slEntryIndex].strFrom), "%s", str);
        
        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strTo, sizeof(pstDbEntry[slEntryIndex].strTo), "%s", str);

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].ucSubject, sizeof(pstDbEntry[slEntryIndex].ucSubject), "%s", str);
        
        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strContent, sizeof(pstDbEntry[slEntryIndex].strContent), "%s", str);
        
        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strAttach, sizeof(pstDbEntry[slEntryIndex].strAttach), "%s", str);

        str = sqlite3_column_text(result, index++);
        if(str)
			snprintf(pstDbEntry[slEntryIndex].strOnlineTime, sizeof(pstDbEntry[slEntryIndex].strOnlineTime), "%s", str);

        slEntryIndex++;
    }  
	sqlite3_finalize(result);

    if(slEntryIndex != slEntryNum)
    {
        INFO("Now select count() is %d ,but get %d ",slEntryNum,slEntryIndex);
    }
    else
    {
        goto err;
    }

    if(NULL != pstDbEntry)
    {
        free(pstDbEntry);
        pstDbEntry = NULL;
    }
err:
    SAFE_DB_CLOSE(db);
	*pslEntryNum = slEntryIndex;
	*ppentry = pstDbEntry;
    return pstDbEntry == NULL ? RET_FAILED : RET_SUCCESS;

}

static inline int do_update_entry(char *strCmd)
{
    DbHandle db = NULL;

    SAFE_DB_OPEN(DATA_BASE_NAME, db);
	SAFE_DB_TIMEOUT(db, 1000);

    SAFE_DB_EXEC(db, strCmd);
	SAFE_DB_CLOSE(db);

	return RET_SUCCESS;
}
/**
 * @brief 
 * 先在当天查找是否有记录过改mac与type
 *    存在
 *        检查value是否相等，如果相等，更新时间
 *        如果不等则表示有两个账号登录过，取出数据，将value值修改后更新
 *    不存在
 *        作为新设备记录
 * @param term 
 * @param type 
 * @return int 
 */
int do_update_terminal(const void *term,void *account,void *entryInfo)
{
    int ret = RET_SUCCESS;
    int slRntryNum = 0;
    char strFindTermSql[MAX_SQL_QUERY_LEN] = {0};
    const TERM_RECORD_INFO   *pstTerminal    = (const TERM_RECORD_INFO *)term;
    const ACCOUNT_TYPE_INFO  *pstAccount     = (const ACCOUNT_TYPE_INFO *)account;
    DATABASE_RECORD_ENTRY    *pstDbEntry     = NULL;
    DATABASE_RECORD_ENTRY    *pstOutEntry    = ( DATABASE_RECORD_ENTRY    *)entryInfo; /*需要传出的数据*/

    const char 				*delim = "+";
    time_t timeNow = time(NULL);
	strftime(pstOutEntry->strActiveTime,128,"%Y-%m-%d %H:%M:%S",localtime(&timeNow));

    snprintf(strFindTermSql,MAX_SQL_QUERY_LEN,
    "select * from record "
    "where  date(online)=date('now') "
    "and "
	"mac='%02x:%02x:%02x:%02x:%02x:%02x' "
	"and "
	"type = '%s'; ",
    pstTerminal->ucMacAddr[0],pstTerminal->ucMacAddr[1],pstTerminal->ucMacAddr[2],
    pstTerminal->ucMacAddr[3],pstTerminal->ucMacAddr[4],pstTerminal->ucMacAddr[5],
    pstAccount->strType
    );
    INFO("-->%s",strFindTermSql);
    if(do_find_terminal(strFindTermSql,&slRntryNum,&pstDbEntry) == RET_SUCCESS && slRntryNum > 0) /*find one*/
    {
        /*
        *   如果找到了就比较value是否相同，如果不同，则表明有新账号登录
        *   更新账号信息，更新个数信息
        * */
        if(slRntryNum == 1)
        {
            //if(pstAccount->num != 1 || strcasecmp(pstDbEntry->strAccountVal,pstAccount->value) != 0)
            //if(strstr(pstDbEntry->strAccountVal,pstAccount->value) == NULL) /*在数据库里面没有*/

            int i = 0;
            char strNewAccount[256] = {0};
            char **arg = calloc(pstAccount->num == 0 ? 1 : pstAccount->num ,sizeof(char *));
            if(arg == NULL)
            {
                WARNING("Not get memory");
                return RET_FAILED;
            }
            char * p = strtok((char *)pstAccount->value,delim);
            while(p != NULL && i < pstAccount->num)
            {
                arg[i] = p;
                p = strtok(NULL,delim);
                i++;
            }
            i = 0;
            strncpy(strNewAccount,pstDbEntry->strAccountVal,sizeof(strNewAccount));
            while(i < pstAccount->num && arg[i])
            {
                if(strstr(strNewAccount,arg[i]))
                {
                    i++;
                    continue;
                }
                memset(pstDbEntry->strAccountVal,0,sizeof(pstDbEntry->strAccountVal));
                snprintf(pstDbEntry->strAccountVal,256,"%s+%s",strNewAccount,arg[i]);
                pstDbEntry->slAcountNum++;
                strncpy(strNewAccount,pstDbEntry->strAccountVal,sizeof(strNewAccount));
                i++;

                INFO("terminal %02x:%02x:%02x:%02x:%02x:%02x type:%s has %d accounts %s ",
                pstTerminal->ucMacAddr[0],pstTerminal->ucMacAddr[1],pstTerminal->ucMacAddr[2],
                pstTerminal->ucMacAddr[3],pstTerminal->ucMacAddr[4],pstTerminal->ucMacAddr[5],
                pstAccount->strType,slRntryNum,strNewAccount);
            }
           
            free(arg);
            arg = NULL;

            memset(strFindTermSql,0,MAX_SQL_QUERY_LEN);
            snprintf(strFindTermSql,MAX_SQL_QUERY_LEN,
            "update record "
            "set "
            "num=%d,value='%s',active='%s' "
            "where  id=%d; ",
            pstDbEntry->slAcountNum,strNewAccount,pstOutEntry->strActiveTime,pstDbEntry->slId);

            INFO("-->%s",strFindTermSql);
            ret = do_update_entry(strFindTermSql);

            strcpy(pstOutEntry->strOnlineTime,pstDbEntry->strOnlineTime);
        }
        else
        {
             /*可能需要先删除*/
             WARNING("database meet a problem,today  terminal %02x:%02x:%02x:%02x:%02x:%02x type:%s has %d entries",
             pstTerminal->ucMacAddr[0],pstTerminal->ucMacAddr[1],pstTerminal->ucMacAddr[2],
             pstTerminal->ucMacAddr[3],pstTerminal->ucMacAddr[4],pstTerminal->ucMacAddr[5],
            pstAccount->strType,slRntryNum);
        }
    }
    else
    {
        strcpy(pstOutEntry->strOnlineTime,pstOutEntry->strActiveTime);
        ret = do_insert_newone(term,account);
    }

    if(pstDbEntry)
    {
        free(pstDbEntry);
        pstDbEntry = NULL;
    }    

    return ret;
}


int do_update_url(void *pstUrlInfo)
{
    DbHandle db=NULL;
    char strFindTermSql[MAX_SQL_QUERY_LEN] = {0};
    HTTP_URL_INFO *pstOptionTmp = ( HTTP_URL_INFO *)pstUrlInfo;
    unsigned int ulIp = pstOptionTmp->addr.saddr;

    snprintf(strFindTermSql,MAX_SQL_QUERY_LEN,
    "insert into  "
    "httplog(mac,ip,value) "
    "values('%02x:%02x:%02x:%02x:%02x:%02x','%s','http://%s%s'); ",
    pstOptionTmp->ucMacAddr[0],pstOptionTmp->ucMacAddr[1],pstOptionTmp->ucMacAddr[2],
    pstOptionTmp->ucMacAddr[3],pstOptionTmp->ucMacAddr[4],pstOptionTmp->ucMacAddr[5],
    int_ntoa (ulIp),
    pstOptionTmp->strHost,pstOptionTmp->strUrl);

    INFO("%s",strFindTermSql);
    SAFE_DB_OPEN_V2(DATA_BASE_NAME, db, SQLITE_OPEN_READWRITE);
	SAFE_DB_TIMEOUT(db, 1000);

    SAFE_DB_EXEC(db,strFindTermSql);

    SAFE_DB_CLOSE(db);

    return RET_SUCCESS;
}
int do_update_email(void *pstemailInfo,void * ipc)
{
    DbHandle db=NULL;
    EMAIL_INSIGHT_IPC *pstNotify = (EMAIL_INSIGHT_IPC *)ipc;
	SMTP_PARSE_INFO *pstEmail    = (SMTP_PARSE_INFO *)pstemailInfo;

    char strEmailSql[2048] = {0};

    snprintf(strEmailSql,2048,
    "insert into "
    "email(mac,ip,user,key,type,emailfrom,emailto,subject,content,attach) "
    "values('%02x:%02x:%02x:%02x:%02x:%02x','%s','%s','%s','%s','%s','%s','%s','%s','%s');",
    pstNotify->ucMac[0],pstNotify->ucMac[1],pstNotify->ucMac[2],
    pstNotify->ucMac[3],pstNotify->ucMac[4],pstNotify->ucMac[5],
    int_ntoa (pstNotify->ulIp),
    pstNotify->strUser,
    pstNotify->strKey,
    pstNotify->emailType == _EMAIL_SMTP ? "s" : "r",
    pstNotify->emailType == _EMAIL_SMTP ? pstNotify->strUser : pstEmail->strSender,
    pstEmail->strTo,
    pstEmail->ucSubject,
    pstEmail->stExtractInfo.strContentFile,
    pstEmail->stExtractInfo.strAttchFile
    );

    SAFE_DB_OPEN_V2(DATA_BASE_NAME, db, SQLITE_OPEN_READWRITE);
	SAFE_DB_TIMEOUT(db, 1000);

    SAFE_DB_EXEC(db,strEmailSql);

    SAFE_DB_CLOSE(db);
   
    return RET_SUCCESS;
}
#else
int do_delete_overtime_term(void)
{
    return RET_SUCCESS;
}
#endif

int virtual_db_init(void)
{   
    #ifndef TRAFFIC_CMCC
	if(access(DATA_BASE_NAME,R_OK) == 0)    /*数据库文件存在*/
    {
		INFO("traffic-insight %s has been existing \n",DATA_BASE_NAME);
        return RET_SUCCESS;
    }

    system("mkdir -p /etc/traffic-insight/");
	unlink(DATA_BASE_NAME);
	DbHandle db;
	
	INFO("traffic-insight Create database [%s] now", DATA_BASE_NAME);
	INFO("traffic-insight Database version is [%s]", sqlite3_libversion());

	SAFE_DB_OPEN_V2(DATA_BASE_NAME, db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	SAFE_DB_TIMEOUT(db, 1000);

	/*终端记录表*/
	SAFE_DB_EXEC(db, CREATE_TERM_RECORD_CMD);

    /*上网日志记录表*/
    SAFE_DB_EXEC(db, CREATE_HTTPLOG_RECORD_CMD);
    
    /*邮件记录表*/
    SAFE_DB_EXEC(db, CREATE_EMAIL_RECORD_CMD);
    
    INFO("traffic-insight Create database successful");
	SAFE_DB_CLOSE(db);
    #endif

    return RET_SUCCESS;
}

