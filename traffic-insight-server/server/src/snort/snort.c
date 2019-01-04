/*
 * @Author: jiamu 
 * @Date: 2018-10-08 14:14:18 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-08 14:16:50
 */
#include "snort.h"
#include "snort_file.h"








int snort_init(void)
{
    snort_init_file(PROFILE_PATH);

    return RET_SUCCESS;
}