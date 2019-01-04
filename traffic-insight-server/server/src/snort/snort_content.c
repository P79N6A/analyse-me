/*
 * @Author: jiamu 
 * @Date: 2018-10-08 15:26:06 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 17:41:01
 * @Brief:
 *  每条规则包含多个选项,每个选项以content开头,可包含offset、eoffset等子选项
 */


#include "snort_content.h"
#include "snort_file.h"
#include "log.h"

static int file_line = 0;
static RULE_CONTENT_MATCH * last   =  NULL;          /*this Is for record one content*/
/*
 *  Function: make_skip(char *, int)
 *  Purpose: Create a Boyer-Moore skip table for a given pattern
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *  Returns:
 *      int * - the skip table
 */
int *
make_skip(char *ptrn, int plen)
{
    int *skip;
    int *sptr;

	skip = malloc(256 * sizeof(int));
	sptr = &skip[256];

    while (sptr-- != skip)
        *sptr = plen + 1;
    while( plen != 0)
        skip[(unsigned char) *ptrn++] = plen--;

    return skip;
}

/*
 *  Function: make_shift(char *, int)
 *  Purpose: Create a Boyer-Moore shift table for a given pattern
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *  Returns:
 *      int * - the shift table
*/
int *
make_shift(char *ptrn, int plen)
{
    int *shift;
    int *sptr;
    char *pptr;
    char c;

	shift = malloc(plen * sizeof(int));
	sptr = shift + plen - 1;
	pptr = ptrn + plen - 1;
	c = ptrn[plen - 1];
    *sptr = 1;

    while (sptr-- != shift) {
		char *p1 = ptrn + plen - 2, *p2, *p3;

        do {
            while(p1 >= ptrn && *p1-- != c);

            p2 = ptrn + plen - 2;
            p3 = p1;
            while(p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr);
        } while(p3 >= ptrn && p2 >= pptr);

        *sptr = shift + plen - sptr + p2 - p3;
        pptr--;
    }

    return shift;
}


static void content_init(char *rule, void *pstRuleDetail, char *file)
{
	RULE_CONTENT_MATCH *tmp, *tmp1;
    char tmp_buf[2048];

    /* got enough ptrs for you? */
    char *start_ptr;
    char *end_ptr;
    char *idx;
    char *dummy_idx;
    char *dummy_end;
    char hex_buf[3];
    int dummy_size = 0;
    int size;
    int hexmode = 0;
    int hexsize = 0;
    int pending = 0;
    int cnt = 0;
    int literal = 0;
    int exception_flag = 0;

    /* clear out the temp buffer */
    bzero(tmp_buf, 2048);

    if (rule == NULL)
        fatal("%s(%d) => parse_content Got Null "
		   "enclosed in quotation marks (\")!\n", file, file_line);
#if 0
    while (isspace((int)*rule))
        rule++;
#endif
    if (*rule == '!')
        exception_flag = 1;

    start_ptr = index(rule, '"');

    if (!start_ptr)
        fatal("%s(%d) => Content data needs to be "
		   "enclosed in quotation marks (\")!\n", file, file_line);

    start_ptr++;
    end_ptr = rindex(start_ptr, '"');

    if (!end_ptr)
        fatal("%s(%d) => Content data needs to be enclosed "
                   "in quotation marks (\")!\n", file, file_line);
    *end_ptr = '\0';
    size = end_ptr - start_ptr;
    if (size <= 0)
        fatal("%s(%d) => Bad pattern length!\n", file, file_line);
    /* set all the pointers to the appropriate places... */
    idx = start_ptr;
    /* set the indexes into the temp buffer */
    dummy_idx = tmp_buf;
    dummy_end = (dummy_idx + size);

    /* why is this buffer so small? */
    bzero(hex_buf, 3);
    memset(hex_buf, '0', 2);

    /* BEGIN BAD JUJU..... */
    while (idx < end_ptr) {
        switch (*idx) {
        case '|':
            if (!literal) {
                if (!hexmode)
                    hexmode = 1;
                else {
                    /*
                    **  Hexmode is not even.
                    */
                    if (!hexsize || hexsize % 2)
                        fatal("%s(%d) => Content hexmode argument has invalid "
                                   "number of hex digits.  The argument '%s' must "
                                   "contain a full even byte string.\n",
                                   file, file_line, start_ptr);
                    hexmode = 0;
                    pending = 0;
                }

                if (hexmode)
                    hexsize = 0;
            } else {
                literal = 0;
                tmp_buf[dummy_size] = start_ptr[cnt];
                dummy_size++;
            }

			break;
        case '\\':
            if (!literal)
                literal = 1;
            else {
                tmp_buf[dummy_size] = start_ptr[cnt];
                literal = 0;
                dummy_size++;
            }

            break;
        case '"':
            if (!literal)
                fatal("%s(%d) => Non-escaped "
                        " '\"' character!\n", file, file_line);
            /* otherwise process the character as default */
        default:
            if (hexmode) {
                if (isxdigit((int) *idx)) {
                    hexsize++;

                    if (!pending) {
                        hex_buf[0] = *idx;
                        pending++;
                    } else {
                        hex_buf[1] = *idx;
                        pending--;

                        if (dummy_idx < dummy_end) {                            
                            tmp_buf[dummy_size] = (u_char) 
                                strtol(hex_buf, (char **) NULL, 16) & 0xFF;

                            dummy_size++;
                            bzero(hex_buf, 3);
                        } else
                            fatal("ParsePattern() dummy "
                                    "buffer overflow, make a smaller "
                                    "pattern please! (Max size = 2048)\n");
                    }
                } else if (*idx != ' ')
                        fatal("%s(%d) => What is this "
                                "\"%c\"(0x%X) doing in your binary "
                                "buffer?  Valid hex values only please! "
                                "(0x0 - 0xF) Position: %d\n",
                                file, file_line, (char) *idx, (char) *idx, cnt);
            } else {
                if (*idx >= 0x1F && *idx <= 0x7e) {
                    if (dummy_idx < dummy_end) {
                        tmp_buf[dummy_size] = start_ptr[cnt];
                        dummy_size++;
                    } else
                        fatal("%s(%d)=> %s "
                                "dummy buffer overflow!\n", file, file_line, __FUNCTION__);

                    if (literal)
                        literal = 0;
                } else {
                    if (literal) {
                        tmp_buf[dummy_size] = start_ptr[cnt];
                        dummy_size++;
                        literal = 0;
                    } else 
                        fatal("%s(%d)=> character value out "
                                "of range, try a binary buffer dude\n", 
                                file, file_line);
                }
            }

            break;
        }

        dummy_idx++;
        idx++;
        cnt++;
    }

    if (literal)
        fatal("%s(%d)=> backslash escape is not "
		   "completed\n", file, file_line);

    if (hexmode)
        fatal("%s(%d)=> hexmode is not "
		   "completed\n", file, file_line);

    tmp = malloc (sizeof(RULE_CONTENT_MATCH) + dummy_size + 1);
    memset(tmp,0,sizeof(RULE_CONTENT_MATCH) + dummy_size + 1);
    
    RULE_DETAIL_INFO * r = (RULE_DETAIL_INFO *)pstRuleDetail;
	tmp1 = (RULE_CONTENT_MATCH *)r->ds_list[RESV_PATTERN_MATCH];

    
	if (!tmp1)
    {
        r->ds_list[RESV_PATTERN_MATCH] = tmp;
    }
	else 
    {
        //insert tail
		for (; tmp1->next; tmp1 = (typeof(tmp1))tmp1->next);
		tmp1->next = (typeof(tmp1->next))tmp;
	}

	tmp->next = NULL;
	last = tmp;
    memcpy(tmp->pattern_buf, tmp_buf, dummy_size);
    tmp->pattern_size = (u_int16_t)dummy_size;
	tmp->n_content    = exception_flag;

    //tmp->search = unisearch;
    // printf("Make skip and shift:size %d buf-->%s \n",tmp->pattern_size,tmp->pattern_buf);
    // tmp->skip_stride = make_skip(tmp->pattern_buf, tmp->pattern_size);
	// tmp->shift_stride = make_shift(tmp->pattern_buf, tmp->pattern_size);
    
}
static void
content_offset(char *data,  void *pstRuleDetail, char *file)
{
    RULE_CONTENT_MATCH *idx = last;

    if (!idx)
        fatal("%s(%d) => Please place \"content\" rules before "
                "depth, nocase or offset modifiers.\n", file, file_line);

	skip_space(data);
    idx->offset = strtol(data, NULL, 10);

    if (errno == ERANGE)
        fatal("ERROR %s Line %d => Range problem on offset value\n", 
                file, file_line);
    if (idx->offset > 65535)
        fatal("ERROR %s Line %d => Offset greater than max Ipv4 "
                "packet size\n", file, file_line);
}


static void
content_eoffset(char *data,  void *pstRuleDetail, char *file)
{
    RULE_CONTENT_MATCH *idx = last;

    if (!idx)
        fatal("%s(%d) => Please place \"content\" rules before "
                "depth, nocase or offset modifiers.\n", file, file_line);

	skip_space(data);
    idx->eoffset = strtol(data, NULL, 10);

    if (errno == ERANGE)
        fatal("ERROR %s Line %d => Range problem on eoffset value\n", 
                file, file_line);
    if (idx->eoffset > 65535)
        fatal("ERROR %s Line %d => eOffset greater than max Ipv4 "
                "packet size\n", file, file_line);
}


static void
content_depth(char *data,  void *pstRuleDetail, char *file)
{
    RULE_CONTENT_MATCH *idx = last;

    if (!idx)
        fatal("%s(%d) => Please place \"content\" rules before "
                "depth, nocase or offset modifiers.\n", file, file_line);
	skip_space(data);
    idx->depth = strtol(data, NULL, 10);

    if (errno == ERANGE)
        fatal("ERROR %s Line %d => Range problem on Depth value\n", 
                file, file_line);
    if (idx->depth > 65535)
        fatal("ERROR %s Line %d => Depth greater than max Ipv4 "
                "packet size\n", file, file_line);
	/*
	 * check to make sure that this the depth allows this rule to fire
	 */
    if (idx->depth != 0 && idx->depth < idx->pattern_size)
        fatal("%s(%d) => The depth(%d) is less than the size of the content(%u)!\n",
                   file, file_line, idx->depth, idx->pattern_size);
}


static void
content_nocase(char *data,  void *pstRuleDetail, char *file)
{
    RULE_CONTENT_MATCH *idx = last;
	int i;

    if (!idx)
        fatal("%s(%d) => Please place \"content\" rules before "
                "depth, nocase or offset modifiers.\n", file, file_line);
	i = idx->pattern_size;
	while (--i >= 0)
		idx->pattern_buf[i] = toupper((unsigned char) idx->pattern_buf[i]);
    
    // printf("Make skip and shift:size %d buf-->%s \n",idx->pattern_size,idx->pattern_buf);
    // idx->skip_stride = make_skip(idx->pattern_buf, idx->pattern_size);
	// idx->shift_stride = make_shift(idx->pattern_buf, idx->pattern_size);
	idx->nocase = 1;
}


static void
content_record(char *data,  void *pstRuleDetail, char *file)
{
    RULE_CONTENT_MATCH *idx = last;
	int8_t	value;

    if (!idx)
        fatal("%s(%d) => Please place \"content\" rules before "
                "depth, nocase or offset modifiers.\n", file, file_line);
	skip_space(data);
    value = (int8_t)strtol(data, NULL, 10);

    if (errno == ERANGE)
        fatal("ERROR %s Line %d => Range problem on 'record' value\n", 
                file, file_line);
    if (value < 0 || value > (INT8_MAX - 1))
        fatal("ERROR %s Line %d => Bad record value.\n", file, file_line);
	idx->record_oft = (uint8_t)value;
	idx->use_record = 1;
}

static void
content_rawbytes(char *data, void *pstRuleDetail, char *file)
{
    RULE_CONTENT_MATCH *idx = last;

    if (!idx)
        fatal("%s(%d) => Please place \"content\" rules before "
                "depth, nocase or offset modifiers.\n", file, file_line);
	idx->rawbytes = 1;
}


static void
content_distance(char *data, void *pstRuleDetail, char *file)
{
    RULE_CONTENT_MATCH *idx = last;

    if (!idx)
        fatal("%s(%d) => Please place \"content\" rules before "
                "depth, nocase or offset modifiers.\n", file, file_line);
	if (!((RULE_CONTENT_MATCH *)((RULE_DETAIL_INFO *)pstRuleDetail)->ds_list[RESV_PATTERN_MATCH])->next)
		fatal("%s(%d) => Distance only can be used for contents num >1.", file, file_line);

	skip_space(data);
    idx->distance = strtol(data, NULL, 10);

    if (errno == ERANGE)
        fatal("ERROR %s Line %d => Range problem on distance value\n", 
                file, file_line);
    if (idx->distance > 65535)
        fatal("ERROR %s Line %d => distance greater than max Ipv4 "
                "packet size\n", file, file_line);
	if (idx->distance)
		idx->use_doe = 1;
}


static void
content_door(char *data, void *pstRuleDetail, char *file)
{
    RULE_CONTENT_MATCH *idx = last;

    if (!idx)
        fatal("%s(%d) => Please place \"content\" rules before "
                "depth, nocase or offset modifiers.\n", file, file_line);
	idx->do_or = 1;
}


const RULE_OPTION_CALLBACK gstRuleOptCb[] =
{
    {"content",	    RESV_PATTERN_MATCH,	content_init,	    },
    {"offset",	    RESV_PATTERN_MATCH,	content_offset,		},
	{"eoffset",	    RESV_PATTERN_MATCH,	content_eoffset,	},
    {"depth",	    RESV_PATTERN_MATCH,	content_depth,		},
    {"nocase",	    RESV_PATTERN_MATCH,	content_nocase,		},
    {"rawbytes",	RESV_PATTERN_MATCH,	content_rawbytes,	},
    {"distance",	RESV_PATTERN_MATCH,	content_distance,	},
	{"record",		RESV_PATTERN_MATCH,	content_record,		},
	{"door",		RESV_PATTERN_MATCH,	content_door        },
};


/**
 * @brief 
 *  将记录的option全部转化为 RULE_CONTENT_MATCH
 * @param strName 
 * @param strKey 
 * @param pstRuleDetail 
 * @param strFile 
 * @return int 
 */
int rule_content_make(char *strName,char *strKey,void *pstRuleDetail,char *strFile)
{
    int i = 0;

    //print("Now make option:%s key:%s \n",strName,strKey);
    for(i = 0;i < sizeof(gstRuleOptCb) / sizeof(gstRuleOptCb[0]);i++)
    {
        if(strcasecmp(gstRuleOptCb[i].strName,strName) == 0)
        {
            
            gstRuleOptCb[i].cbOptionHandle(strKey,pstRuleDetail,strFile);
            return RET_SUCCESS;
        }
    }
    
    if(i == sizeof(gstRuleOptCb) / sizeof(gstRuleOptCb[0]))
    {
        fatal("invalid option：%s \n",strName);
    }
    return RET_SUCCESS;
}

/**
 * @brief 
 *  生成算法stride和shift所使用的參數
 * @param pstRuleDetail 
 */
void rule_content_stride_make(void *pstRuleDetail)
{

    RULE_DETAIL_INFO * r = (RULE_DETAIL_INFO *)pstRuleDetail;
	RULE_CONTENT_MATCH *pstContent = (RULE_CONTENT_MATCH *)r->ds_list[RESV_PATTERN_MATCH];
    RULE_CONTENT_MATCH *pstContentTmp = pstContent;

    if(pstContent == NULL)
    {
        fatal("There is no content \n");
    }

    for (; pstContentTmp != NULL; pstContentTmp = (typeof(pstContentTmp))pstContentTmp->next)
    {
        //printf("make shift and skip:%s \n",pstContentTmp->pattern_buf);
        pstContentTmp->skip_stride  = make_skip(pstContentTmp->pattern_buf, pstContentTmp->pattern_size);
	    pstContentTmp->shift_stride = make_shift(pstContentTmp->pattern_buf, pstContentTmp->pattern_size);
    }
}

/* url decode */
int ConvertUrlToAscii(char *dest, int destSize, const char *src, int srcSize)
{
	char *dhead = dest;
	char	val;
	int i, j;

	if (dest == NULL || src == NULL || srcSize <= 1) {
		printpkt("params error! (%d,%d,%d<=1)\n", dest == NULL, src == NULL, srcSize);
		return -1;
	}

	memset (dest, 0, destSize);

	for (i = 0; (i < destSize) && (srcSize > 0); ++i) {
		if (*src == '%') {
			++src;
			--srcSize;
			if (isxdigit(src[0]) && isxdigit(src[1])) {
				for (val = 0, j = 0; j < 2; ++j, ++src, --srcSize) {
					val <<= 4;
					if (isdigit(*src)) {
						val += (*src - '0');
					} else if (isupper(*src)) {
						val += (*src - 'A' + 10);
					} else {
						val += (*src - 'a' + 10);
					}
				}

		    		//printpkt("in src(%d, %#x, %#x) --> val [%#x]",srcSize,src[0],src[1],val&0xFF);
	    			*dest++ = val;
		  	} else {
		    		memset (dest, 0, destSize);
		    		printpkt("src (%#x, %#x) not xdigit\n", src[0], src[1]);
		    		return -1;
		  	}
		} else {
			*dest++ = *src;
			++src;
			--srcSize;
		}
	}

	if (srcSize < 0) {
		printpkt("srcSize %d < 0, something error? src [%s] ", srcSize, src);
		printpkt("convert dest=[%s]",dhead);
	}

	return i;
}

/* convert unicode to utf8 */
int ConvertUnicodeToUtf8Helper(unsigned long uni, unsigned char *pOut, int outSize)
{
	if (pOut == NULL) {
		printpkt("params error! pOut == NULL");
		return -1;
	}
	if (outSize < 6) {
		printpkt("params error! outSize %d < 6", outSize);
		return -1;
	}

	//memset (pOut, 0, outSize);
	if ( uni <= 0x0000007F )
	{
		// * U-00000000 - U-0000007F:  0xxxxxxx
		*pOut	= (uni & 0x7F);
		return 1;
	}
	else if ( uni >= 0x00000080 && uni <= 0x000007FF )
	{
		// * U-00000080 - U-000007FF:  110xxxxx 10xxxxxx
		*(pOut+1) = (uni & 0x3F) | 0x80;
		*pOut     = ((uni >> 6) & 0x1F) | 0xC0;
		return 2;
	}
	else if ( uni >= 0x00000800 && uni <= 0x0000FFFF )
	{
		// * U-00000800 - U-0000FFFF:  1110xxxx 10xxxxxx 10xxxxxx
		*(pOut+2) = (uni & 0x3F) | 0x80;
		*(pOut+1) = ((uni >>  6) & 0x3F) | 0x80;
		*pOut     = ((uni >> 12) & 0x0F) | 0xE0;
		printpkt("convt %#x,%#x,%#x", *pOut, *(pOut+1), *(pOut+2));
		return 3;
	}
	else if ( uni >= 0x00010000 && uni <= 0x001FFFFF )
	{
		// * U-00010000 - U-001FFFFF:  11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
		*(pOut+3) = (uni & 0x3F) | 0x80;
		*(pOut+2) = ((uni >>  6) & 0x3F) | 0x80;
		*(pOut+1) = ((uni >> 12) & 0x3F) | 0x80;
		*pOut     = ((uni >> 18) & 0x07) | 0xF0;
		return 4;
	}
	else if ( uni >= 0x00200000 && uni <= 0x03FFFFFF )
	{
		// * U-00200000 - U-03FFFFFF:  111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
		*(pOut+4) = (uni & 0x3F) | 0x80;
		*(pOut+3) = ((uni >>  6) & 0x3F) | 0x80;
		*(pOut+2) = ((uni >> 12) & 0x3F) | 0x80;
		*(pOut+1) = ((uni >> 18) & 0x3F) | 0x80;
		*pOut     = ((uni >> 24) & 0x03) | 0xF8;
		return 5;
	}
	else if ( uni >= 0x04000000 && uni <= 0x7FFFFFFF )
	{
		// * U-04000000 - U-7FFFFFFF:  1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
		*(pOut+5) = (uni & 0x3F) | 0x80;
		*(pOut+4) = ((uni >>  6) & 0x3F) | 0x80;
		*(pOut+3) = ((uni >> 12) & 0x3F) | 0x80;
		*(pOut+2) = ((uni >> 18) & 0x3F) | 0x80;
		*(pOut+1) = ((uni >> 24) & 0x3F) | 0x80;
		*pOut     = ((uni >> 30) & 0x01) | 0xFC;
		return 6;
	}

	return 0;
}


/* Convert Native string("%5CuXXXX") to Ascii string */  
/* If the native string header has "\u", that indicates it is hexadecimal coding string(should always this format:"%5CuXXXX") */
int ConvertNativeToAscii(char *dest, int destSize, const char *src, int srcSize)
{
	const char *uni_header = "%5Cu";
	int i, j;
	unsigned long val = 0;
	int valLen = 0;
	char *ptr = NULL;
	char *d = dest;
	int dLen = destSize;
	int curr_uni_sz = 0;

	if (dest == NULL || destSize <= 1 || src == NULL || srcSize <= 1) {
		printpkt("params error! (%d,%d<=1, %d,%d<=1)\n",
			dest == NULL, destSize, src == NULL, srcSize);
		return -1;
	}

	memset (dest, 0, destSize);

	for (i = 0; i < srcSize; ) {
		if (((srcSize - i) > strlen(uni_header)) && (0 == strncasecmp(src+i, uni_header, strlen(uni_header)))) {
			i += strlen(uni_header);

			// check current unicode chars size
			ptr = strnstr(src+i, "%", srcSize-i);
			if (ptr != NULL) {
				curr_uni_sz = ptr - (src+i);
			} else {
				curr_uni_sz = srcSize - i;
			}
			if (curr_uni_sz < 4) {
				printpkt("error unicode len %d < 4, found uni char %d", curr_uni_sz, (ptr != NULL));
				return -1;
			}

			val = 0;
			for (j=0; j < 4; j++) {
				unsigned char jc = 0, sc = 0;
				sc = src[i+j];
				if (sc >= '0' && sc <= '9') {
					jc = sc - '0';
				} else if (sc >= 'A' && sc <= 'F') {
					jc = sc - 'A' + 0xA;
				} else if (sc >= 'a' && sc <= 'f') {
					jc = sc - 'a' + 0xA;
				} else {
					printpkt("src[%d] %c is invalid hexadecimal coding string", i+j, sc);
					return -1;
				}
				val <<= 4;
				val += jc;
				//printpkt("src[%d]=%c, jc=%#x, val = %#lx", i+j, sc, jc, val);
			}

			valLen = ConvertUnicodeToUtf8Helper(val, d, dLen);
			if (valLen <= 0) {
				printpkt("convt err, unicode out [%s]", dest);
				return -1;
			}

			//printpkt("convert current char [%s] ok, (valLen %d, dLen %d)", d, valLen, dLen);
			d += valLen;
			dLen -= valLen;
			i += 4;
		} else { //normal string, just copy
			*d++ = src[i];
			--dLen;
			++i;
		}
	}
	//printpkt("unicode final dest [%s], dLen=%d (%d), ret len=%d\n", dest, dLen, destSize, destSize-dLen);
	return (destSize-dLen);
}
