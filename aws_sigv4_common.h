#ifndef __AWS_SIGV4_COMMON_H
#define __AWS_SIGV4_COMMON_H

/*
 * sigv4 util code is from https://github.com/sidbai/aws-sigv4-c
 * the only difference is here we use ngx_str_t.
 */
#include <ngx_core.h>
typedef ngx_str_t aws_sigv4_str_t;

aws_sigv4_str_t aws_sigv4_string(const unsigned char* cstr);

int aws_sigv4_strncmp(aws_sigv4_str_t* str1, aws_sigv4_str_t* str2);

int aws_sigv4_empty_str(aws_sigv4_str_t* str);

int aws_sigv4_sprintf(unsigned char* buf, const char* fmt, ...);

int aws_sigv4_snprintf(unsigned char* buf, unsigned int n, const char* fmt, ...);

#endif /* __AWS_SIGV4_COMMON_H */
