#ifndef _NGX_HTTP_AWS_SIGV4_REQUEST_MODELE_H_INCLUDED_
#define _NGX_HTTP_AWS_SIGV4_REQUEST_MODELE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t   access_key_id;
    ngx_str_t   secret_access_key;
    ngx_str_t   aws_region;
    ngx_str_t   aws_service_name;
    ngx_str_t   aws_service_endpoint;
} ngx_http_aws_sigv4_request_conf_t;

#endif // _NGX_HTTP_AWS_SIGV4_REQUEST_MODELE_H_INCLUDED_
