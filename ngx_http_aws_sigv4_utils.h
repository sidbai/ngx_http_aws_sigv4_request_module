#ifndef _NGX_HTTP_AWS_SIGV4_UTILS_H_INCLUDED_
#define _NGX_HTTP_AWS_SIGV4_UTILS_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_http.h>

/* sigv4 util code is from https://github.com/sidbai/aws-sigv4-c */
#define AWS_SIGV4_MEMORY_ALLOCATION_ERROR  -2
#define AWS_SIGV4_INVALID_INPUT_ERROR      -1
#define AWS_SIGV4_OK                        0

typedef enum {
    aws_sigv4_signed_payload = 0,
    aws_sigv4_unsigned_payload
} aws_sigv4_payload_sign_opt_e;

typedef struct aws_sigv4_kv_s {
    ngx_str_t key;
    ngx_str_t value;
} aws_sigv4_kv_t;

typedef aws_sigv4_kv_t aws_sigv4_header_t;

typedef struct aws_sigv4_params_s {
    /* AWS credential parameters */
    ngx_str_t                     secret_access_key;
    ngx_str_t                     access_key_id;

    /* HTTP request parameters */
    ngx_str_t                     method;
    ngx_str_t                     uri;
    ngx_str_t                     query_str;
    ngx_str_t                     host;
    /* x-amz-date header value in ISO8601 format */
    ngx_str_t                     x_amz_date;
    ngx_str_t                     payload;
    aws_sigv4_payload_sign_opt_e  payload_sign_opt;

    /* AWS service parameters */
    ngx_str_t                     service;
    ngx_str_t                     region;

    /* cached values for perf improvement */
    ngx_str_t                    *cached_signing_key;
    ngx_str_t                    *cached_date_yyyymmdd;
} aws_sigv4_params_t;

/** @brief perform sigv4 signing
 *
 * @param[in] req           A pointer to nginx http request struct
 * @param[in] sigv4_params  A pointer to a struct of sigv4 parameters
 * @param[out] auth_header  A struct to store Authorization header name and value
 * @return Status code where zero for success and non-zero for failure
 */
int aws_sigv4_sign(ngx_http_request_t* req,
                   aws_sigv4_params_t* sigv4_params,
                   aws_sigv4_header_t* auth_header);

#endif /* _NGX_HTTP_AWS_SIGV4_UTILS_H_INCLUDED_ */
