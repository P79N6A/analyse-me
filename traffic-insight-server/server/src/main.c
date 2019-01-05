/*
 * @Author: jiamu 
 * @Date: 2018-09-27 13:53:29 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-15 17:15:51
 */

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <string.h>
#include <dirent.h>
#include "im_config.h"
#include "im_main.h"
#include "daq_init.h"
#include "snort.h"
#include "record_data.h"
#include "snort_http.h"
#include "log.h"
#include "ipc.h"
#include "record_db.h"
#include "cJSON.h"

#define LISTEN_IF_NAME  "br-"
#define LISTEN_IF_FILE "/etc/traffic-insight/interface.json"
const char * valid_options = "?c:Dh";

typedef struct
{
    pid_t pid;
    unsigned char data[512];
}MONITOR_INFO;

int ipcFds[2] = {0};
static struct ev_loop *eventLoop;
static int slSubProNum = 0;
static MONITOR_INFO   *gpstListen = NULL;
static ev_timer listen_watcher;

extern NIDS_IF_INFO stIfInfo;
extern int snort_do_detect(void *tuple,void *data,int slDataLen,int slProtocol,void *ethInfo,void * conn);
extern int email_test(void);

/**
 * @brief 
 *  intput a qq stream
 * @return int 
 */
int acs_match_test(void)
{
    const char *strFileName = "/tmp/ganji.bin";
    if(access(strFileName,R_OK) != 0)
    {
        printf("No input data \n");
        return RET_FILEERR;
    }
    struct stat stFileInfo;
    memset(&stFileInfo,0,sizeof(stFileInfo));

    if (stat(strFileName, &stFileInfo) < 0) 
    {
        return RET_FILEERR;
    }

    unsigned char *ucFileData = (unsigned char *)calloc(1,stFileInfo.st_size + 128);
    if(ucFileData == NULL)
    {
        return RET_FILEERR;
    }
    bzero(ucFileData,stFileInfo.st_size + 128);

    int fd = open(strFileName,O_RDONLY);
    if(fd < 0)
    {
        free(ucFileData);
        return RET_FILEERR;
    }
    read(fd,ucFileData,stFileInfo.st_size);
    close(fd);

    /*
    *   做基本解析
    *   不检查VLAN和IP分片
    *   只处理tcp在建立连接之后的数据
    */
    // struct tuple4 addr;
    // struct ethhdr *pstEthInfo = (struct ethhdr *)ucFileData;
    // struct ip     *iph        = (struct ip     *)(pstEthInfo + 1);
    // if (iph->ip_p != IPPROTO_TCP) 
    // {
    //     free(ucFileData);
    //     return RET_FILEERR;
    // }
    // struct tcphdr *this_tcphdr = (struct tcphdr *)((unsigned char *)iph + 4 * iph->ip_hl);

    // addr.source = ntohs(this_tcphdr->th_sport);
    // addr.dest   = ntohs(this_tcphdr->th_dport);
    // addr.saddr  = iph->ip_src.s_addr;
    // addr.daddr  = iph->ip_dst.s_addr;
    // unsigned char *payload = ((unsigned char *)this_tcphdr) + 32;
    struct tuple4 addr;
    struct ethhdr stEthInfo;
    addr.source = 60411;
    addr.dest   = 80;
    addr.saddr  = 0x0337a8c0;
    addr.daddr  = 0x0337a8c0 + 1;
    NIDS_CONNTRACK_RECORD stConn;
    bzero(&stConn,sizeof(stConn));
    stConn.eDir = IP_CT_DIR_ORIGINAL;
    stConn.eMainType = CONN_MAIN_INVALID;
    stConn.eSubType  = 0;

    printf("Now do test %d \n",stFileInfo.st_size);
    snort_do_detect(&addr,ucFileData,
            stFileInfo.st_size,IPPROTO_TCP,&stEthInfo,&stConn);
    free(ucFileData);
    return RET_SUCCESS;
}
/**
 * @brief 
 * 需要考虑在常规linux环境和以后的dpdk环境
 * 两者之间主要是在daq中体现
 *  1.解析配置文件
 *  2.解析规则文件，并初始化规则链
 *  3.启动调试机制模块，用于测试正在运行中的模块
 *  4.启动daq模块
 *  5.启动审计事件
 * @param mode 
 *  1.考虑是linux或dpdk
 *  2.或者是本身运行的模式ids,log,dump
 * @param loop 
 *  main loop
 * @return int 
 *  返回值
 */
int virtual_main(int mode,struct ev_loop *loop)
{
    snort_init();

    record_init(loop);

    http_insight_init(loop);

    //email_test();
    
    acs_match_test();
    
    init_heart_beat(loop);

    //daq_init(mode,loop);

    return RET_SUCCESS;
}
void listen_cb(struct ev_loop *loop, ev_timer *watcher, int revents)
{
    int i = 0;
    int n = 0;
    struct dirent **namelist;
    struct stat stFileInfo;
	char strFileName[512] = {0};

    /*监控子进程信息*/
    for(i = 0;i < slSubProNum;i++)
    {
        bzero(strFileName,sizeof(strFileName));
        snprintf(strFileName,sizeof(strFileName),"/proc/%d",gpstListen[i].pid);

        if(access(strFileName,R_OK) != 0)
        {
            WARNING("subprocess that pid is %d exited",gpstListen[i].pid);
        }
    }
    
    /*监控虚拟身份采集,上网日志,邮件信息数据库*/
    do_delete_overtime_term();

    /**
     * 监控邮件文件,超时时间不采用当前时间
     * 比如现在是10月,删除九月之前的数据
     * */
    time_t nowTime     = time(NULL);
    struct tm *nowtm   = localtime(&nowTime);
    if(nowtm->tm_mon == 0)
	{
		nowtm->tm_mon  = 11;
		nowtm->tm_year = nowtm->tm_year - 1;
	}
	else
	{
		nowtm->tm_mon  = nowtm->tm_mon - 1;
	}
	nowtm->tm_mday  = 1;
	nowtm->tm_hour  = 0;
	nowtm->tm_min   = 0;
	nowtm->tm_sec   = 0;
	time_t nowmk    = mktime(nowtm); /*这个时间是上个月月初凌晨的时间*/
    
    char *strEmailFile[] = {ATTACH_SAVE_PATH,EMAIL_TMP_PATH};
    unsigned int overtime[] = {nowmk,nowTime - 600};

    for(i = 0;i < ARRAY_SIZE(strEmailFile);i++)
    {
        n = scandir(strEmailFile[i], &namelist, NULL, NULL);
        if (n == -1) 
        {
            WARNING("open email dir failed");
            perror("scandir");
            return;
        }
        while (n--) 
        {
            if(strcmp(namelist[n]->d_name,".") == 0 || strcmp(namelist[n]->d_name,"..") == 0)
            {
                //printf("%s\n", namelist[n]->d_name);
                free(namelist[n]);
                continue;
            }

            bzero(strFileName,sizeof(strFileName));
            bzero(&stFileInfo,sizeof(stFileInfo));
            snprintf(strFileName,sizeof(strFileName),"%s%s",strEmailFile[i],namelist[n]->d_name);
            
           // printf("%s\n", strFileName);
            if(stat(strFileName,&stFileInfo) == 0)
            {
                if(stFileInfo.st_mtime < overtime[i])
                {
                        INFO("email file %s need delete from filesystem \n",strFileName);
                        unlink(strFileName);
                }
            }
            free(namelist[n]);
        }
        free(namelist);
    }
}

void moniter_event_init(void *loop)
{
    printf("Now create %d sub process \n",slSubProNum);
    
    ev_timer_init(&listen_watcher, listen_cb, 120, 404);
	ev_timer_start(loop, &listen_watcher);
}
/**
 * @brief 
 * 主进程负责对外接口
 * 比如ubus，数据库
 * 同时负责接收子进程的数据
 * 对辟邪必要的数据进行分析处理
 * 
 * @param arg 
 * @return int 
 */
int main_process_init(void *arg)
{
    close(ipcFds[1]);
    eventLoop = ev_default_loop(0);

    virtual_db_init();
    
    virtual_ubus_init(eventLoop);
    
    init_read_event(eventLoop,ipcFds[0]);

    moniter_event_init(eventLoop);

    ev_loop(eventLoop, 0);
    return RET_FAILED;
}
void catchsig(int sig)
{
    printf("i am %d signal\n", sig);
    if(SIGCHLD == sig)
    {
        ERROR("child process exit,Now need restart app");
        exit(1);
    }
}
/**
 * @brief 
 *  子进程负责数据的采集和分析
 *  将分析结果传递给主进程
 * @param arg 
 * @return int 
 */
int sub_process_bind(void *arg)
{
    cpu_set_t mask;
    int num = get_nprocs();

    CPU_ZERO(&mask);
    CPU_SET(0, &mask);

    if (sched_setaffinity(0, sizeof(mask), &mask) < 0)
    {
         printf("Set CPU affinity failue, ERROR:%s\n", strerror(errno));
         return RET_FAILED; 
    }   

    return RET_SUCCESS;
}
int sub_process_init(void *arg)
{
    close(ipcFds[0]);

    prctl(PR_SET_PDEATHSIG, SIGKILL);  

    //sub_process_bind(arg);

    eventLoop = ev_default_loop(0);

    init_write_fd(ipcFds[1],eventLoop);

    virtual_main(_WORK_LINUX,eventLoop);

    ev_loop(eventLoop, 0);

    return RET_FAILED;
}
typedef struct
{
    char strName[64];
}LISTEN_INTERFACE;

static int parse_listen_file(char *strFileName,LISTEN_INTERFACE **ppstInfo)
{
    struct stat stFileInfo;
    memset(&stFileInfo,0,sizeof(stFileInfo));

    if (stat(strFileName, &stFileInfo) < 0) 
    {
        return RET_FILEERR;
    }

    unsigned char *ucFileData = (unsigned char *)calloc(1,stFileInfo.st_size + 128);
    if(ucFileData == NULL)
    {
        return RET_FILEERR;
    }
  
    bzero(ucFileData,stFileInfo.st_size + 128);

    int fd = open(strFileName,O_RDONLY);
    if(fd < 0)
    {
        free(ucFileData);
        return RET_FILEERR;
    }
    read(fd,ucFileData,stFileInfo.st_size);
    close(fd);

    cJSON *root = cJSON_Parse((char *)ucFileData);
    if(NULL == root)
    {
        printf("Error before: [%s]\n",cJSON_GetErrorPtr());
        free(ucFileData);
        return -1;
    }
	cJSON *nameJson     = cJSON_GetObjectItem(root,"name");
	printf("interface info name %s \n",nameJson ? nameJson->valuestring : "unknown");
	cJSON *ruleJson  = cJSON_GetObjectItem(root,"interface");
    if(NULL == ruleJson)
    {
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
        free(ucFileData);
        return -1;
    }

	int i = 0;
	int ruleNums = cJSON_GetArraySize(ruleJson);
    if(ruleNums == 0 || ruleNums > 20)
    {
        ERROR("Now get wrong interface num %d",ruleNums);
        free(ucFileData);
        return -1;
    }
    LISTEN_INTERFACE *pstIf = calloc(ruleNums,sizeof(LISTEN_INTERFACE));
    if(pstIf == NULL)
    {
        free(ucFileData);
        return -1;
    }
    
	for(i = 0;i < ruleNums;i++)
	{
		cJSON *objectJson = cJSON_GetArrayItem(ruleJson,i);
		if(!objectJson)
        {
            free(pstIf);
            free(ucFileData);
       	 	return -1;
        }

		cJSON *suffixJson = cJSON_GetObjectItem(objectJson,"if-name");
		if(!suffixJson)
        {
            free(pstIf);
            free(ucFileData);
       	 	return -1;
        }
		strncpy(pstIf[i].strName,suffixJson->valuestring,sizeof(pstIf[i].strName));
	}

	free(ucFileData);
	ucFileData = NULL;

    *ppstInfo = pstIf;

    return ruleNums;
}

#ifdef _COMPILE_MAIN_


int main(int argc,char *argv[])
{   
    pid_t pid = -1;
    int i = 0,num = 0;
    int ch; 
    int isDeamon = 0;
    LISTEN_INTERFACE *pstIf = NULL;

	NIDS_IF_INFO stInfo[30];
    bzero(stInfo,sizeof(stInfo));
    const char strListenFile[256] = {0};

    while((ch = getopt(argc, argv, valid_options)) != -1)
    {
        switch(ch)
        {
            case 'c':
                strncpy(strListenFile,optarg,256);
                if(access(strListenFile,R_OK) != 0)
                {
                    fatal("Now get a invalid interface config file %s",strListenFile);
                }
            break;
            case 'D':
                isDeamon = 1;
            break;
            case 'h':
                printf("Usage:\n -D means that deamon and -c can specical interface file");
            break;
            default:
                fatal("wrong args");
        }
       
    }
    if(isDeamon)
    {
        if (daemon(0, 0) < 0)
		{
			fatal("Cannot run as daemon:%s", strerror(errno));
		}
    }
    if(strlen(strListenFile) == 0)
    {
        strncpy(strListenFile,LISTEN_IF_FILE,256);
    }

    if(socketpair(AF_UNIX, SOCK_DGRAM, 0, ipcFds) < 0)
	{
		return RET_FAILED;
	}
    #if 0
    num = nids_getif_info(NULL,(unsigned char *)stInfo); /*should input nids_params.device*/
    if(num < 0)
	{
		fatal("get interface info failed \n");
	}
    #else
    num = parse_listen_file(strListenFile,&pstIf);
    if(num < 1)
    {
        fatal("Not get any interface");
    }
    #endif
    for(i = 0;i < num;i++)
    {   
        bzero(&stIfInfo,0);
        #if 0
        printf("Now get if:%s ip:%08x mask:%08x \n",stInfo[i].ifName,stInfo[i].ulIp,stInfo[i].ulMask);
		if(strncasecmp(stInfo[i].ifName,LISTEN_IF_NAME,strlen(LISTEN_IF_NAME))  || stInfo[i].ulIp == 0)
        {
            continue;
        } 
        stIfInfo = stInfo[i];
        #else
        printf("Now get interface %s info\n",pstIf[i].strName);
        if(nids_getif_info(pstIf[i].strName,(unsigned char *)&stIfInfo) < 0)
        {
            fatal("get interface %s info failed",pstIf[i].strName);
        }
        #endif
      
        printf("capture interface is %s ulNetNum:%08x\n",stIfInfo.ifName,stIfInfo.ulIp);
        pid = fork();
		if(pid < 0 || pid == 0)
		{
			break;
		}

        slSubProNum++;
        if(gpstListen != NULL)
        {
            void *tmp = realloc(gpstListen,slSubProNum * sizeof(*gpstListen));
            if(tmp == NULL)
            {
                 fatal("Get mem failed");
            }
            gpstListen = tmp;
        }
        else
        {
            gpstListen = calloc(1,sizeof(*gpstListen));
            if(gpstListen == NULL)
            {
                 fatal("Get mem failed");
            }
        }

        gpstListen[slSubProNum - 1].pid = pid;
        memcpy(gpstListen[slSubProNum - 1].data,&stIfInfo,sizeof(stIfInfo));
    }
  
    if(pid < 0)
	{
		printf("Frok err \n");
		return RET_FAILED;
	}
	else if(pid == 0)
    {
        return sub_process_init(NULL);
    }
    else
    {
        signal(SIGCHLD, catchsig);

        return main_process_init(NULL);
    }
  
    return RET_FAILED;
}
#endif





