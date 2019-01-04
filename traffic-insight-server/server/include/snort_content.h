/*
 * @Author: jiamu 
 * @Date: 2018-10-08 15:26:13 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 17:42:17
 */

#ifndef _SNORT_CONTENT_H_
#define _SNORT_CONTENT_H_
#include "im_config.h"


#define PROT_HASH_NUM			(8)
#define PROT_HASH_SZIE 			(1<<PROT_HASH_NUM)
#define PORT_HASH_MASK			(PROT_HASH_SZIE - 1)

typedef enum {
	RESV_UNSPEC,
	RESV_PATTERN_MATCH = RESV_UNSPEC,
	RESV_MAX,
} resv_type_t;

typedef enum {
	PAT_ACSM2 = 1,
} pat_arm_type_t;

typedef struct _content_match {
	void *    next;                 /* ptr to next match struct */	
   	u_int16_t offset;             /* pattern search start offset */
	u_int16_t eoffset;			  /* pattern search start from end of payload offset */
    u_int16_t depth;              /* pattern search depth */
    u_int16_t distance;           /* offset to start from based on last match */

	u_int16_t rawbytes:1;           /* Search the raw bytes rather than any decoded app
                               		buffer */
    u_int16_t nocase:1;             /* Toggle case insensitity */
	u_int16_t use_doe:1;            /* Use the doe_ptr for relative pattern searching */
	u_int16_t n_content:1;			/* match not current content. */
	u_int16_t use_record:1;			/* record current ptr. */
	u_int16_t do_or:1;				/* or. */
	u_int16_t record_oft:8;			/* record current ptr offset. */

    u_int16_t pattern_size;    		/* size of app layer pattern */

	int (*search)(char *data, int len, struct _content_match *);  /* search function */
    int *skip_stride;			/* B-M skip array */
    int *shift_stride;			/* B-M shift array */
    char pattern_buf[0];		/* app layer pattern to match on */
} RULE_CONTENT_MATCH;



//for make option match struct by option name + key
typedef void (*optionParse)(char *strOptVal, void *pstOptionHead, char *file);

typedef struct
{
    const char *strName;
    int   slPrio;                  
    optionParse cbOptionHandle;
}RULE_OPTION_CALLBACK;


typedef struct
{
    unsigned short   usPort;
    struct list_head stSrcList[PROT_HASH_SZIE];
    struct list_head stDstList[PROT_HASH_SZIE];
}RULE_PORT_GROUP;

int rule_content_make(char *strName,char *strKey,void *pstRuleDetail,char *strFile);
void rule_content_stride_make(void *pstRuleDetail);

int ConvertUnicodeToUtf8Helper(unsigned long uni, unsigned char *pOut, int outSize);
int ConvertNativeToAscii(char *dest, int destSize, const char *src, int srcSize);
int ConvertUrlToAscii(char *dest, int destSize, const char *src, int srcSize);
#endif
