#include "ngx_http_aws_sigv4_request_module.h"

static ngx_int_t ngx_http_aws_sigv4_request_init(ngx_conf_t *cf);

static char *ngx_http_aws_sigv4_request_key_set(ngx_conf_t *cf,
                                                ngx_command_t *cmd,
                                                void *conf);

static char *ngx_http_aws_sigv4_request_service_set(ngx_conf_t *cf,
                                                    ngx_command_t *cmd,
                                                    void *conf);

static ngx_command_t  ngx_http_aws_sigv4_request_commands[] = {

    { ngx_string("aws_key_path"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_aws_sigv4_request_key_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("aws_service"),
      NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_aws_sigv4_request_service_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t ngx_http_aws_sigv4_request_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_aws_sigv4_request_init,          /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */
    NULL,                                     /* create location configuration */
    NULL                                      /* merge location configuration */
};

ngx_module_t  ngx_http_aws_sigv4_request_module = {
    NGX_MODULE_V1,
    &ngx_http_aws_sigv4_request_module_ctx,   /* module context */
    ngx_http_aws_sigv4_request_commands,      /* module directives */
    NGX_HTTP_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_aws_sigv4_request_init(ngx_conf_t *cf)
{
    return NGX_OK;
}

static char *ngx_http_aws_sigv4_request_key_set(ngx_conf_t *cf,
                                                ngx_command_t *cmd,
                                                void *conf)
{
    return NGX_CONF_OK;
}

static char *ngx_http_aws_sigv4_request_service_set(ngx_conf_t *cf,
                                                    ngx_command_t *cmd,
                                                    void *conf)
{
    return NGX_CONF_OK;
}
