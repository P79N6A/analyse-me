/*
 * @Author: jiamu 
 * @Date: 2018-09-27 14:25:46 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-09-27 16:33:33
 * @brief:for other users
 */


#ifndef _IM_MAIN_H_
#define _IM_MAIN_H_

#include <ev.h>

typedef enum
{
    _WORK_LINUX = 0,
    _WORK_DPDK
}ENUM_WORK_MODE;

int virtual_main(int mode,struct ev_loop *loop);

#endif
