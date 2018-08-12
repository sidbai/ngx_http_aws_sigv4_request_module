#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_aws_sigv4_utils.h"

typedef struct {
    ngx_flag_t  aws_sigv4_enabled;
    ngx_str_t   access_key_path;
    ngx_str_t   access_key_id;
    ngx_str_t   secret_access_key;
    ngx_str_t   aws_region;
    ngx_str_t   aws_service_name;
    ngx_str_t   aws_service_endpoint;
    ngx_str_t   internal_uri;
} ngx_http_aws_sigv4_request_conf_t;

typedef struct {
    ngx_str_t   sigv4_host;
    ngx_str_t   sigv4_uri;
    ngx_str_t   sigv4_x_amz_date;
    ngx_str_t   sigv4_authorization;
} ngx_http_aws_sigv4_request_ctx_t;

static ngx_int_t ngx_http_aws_sigv4_request_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_aws_sigv4_request_variable_handler(ngx_http_request_t *r,
                                                             ngx_http_variable_value_t *v,
                                                             uintptr_t data);

static void *ngx_http_aws_sigv4_request_create_conf(ngx_conf_t *cf);

static char *ngx_http_aws_access_key_path_set(ngx_conf_t *cf,
                                              ngx_command_t *cmd,
                                              void *conf);

static char *ngx_http_aws_service_set(ngx_conf_t *cf,
                                      ngx_command_t *cmd,
                                      void *conf);

static char *ngx_http_aws_sigv4_request_set(ngx_conf_t *cf,
                                            ngx_command_t *cmd,
                                            void *conf);

static ngx_int_t ngx_http_aws_sigv4_request_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_aws_sigv4_request_handler(ngx_http_request_t *r);

static ngx_command_t  ngx_http_aws_sigv4_request_commands[] = {

    { ngx_string("aws_access_key_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_aws_access_key_path_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("aws_service"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_aws_service_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("aws_sigv4_request"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_aws_sigv4_request_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t ngx_http_aws_sigv4_request_module_ctx = {
    ngx_http_aws_sigv4_request_add_variables,     /* preconfiguration */
    ngx_http_aws_sigv4_request_init,              /* postconfiguration */
    NULL,                                         /* create main configuration */
    NULL,                                         /* init main configuration */
    NULL,                                         /* create server configuration */
    NULL,                                         /* merge server configuration */
    ngx_http_aws_sigv4_request_create_conf,       /* create location configuration */
    NULL                                          /* merge location configuration */
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

enum {
    /* nginx variable for aws service endpoint */
    ngx_http_aws_sigv4_var_host,
    /* nginx variable for sigv4 request uri */
    ngx_http_aws_sigv4_var_uri,
    /* nginx variable for sigv4 request X-AMZ-DATE header value */
    ngx_http_aws_sigv4_var_x_amz_date,
    /* nginx variable for sigv4 request Authorization header value */
    ngx_http_aws_sigv4_var_authorization
} ngx_http_aws_sigv4_var_type_e;

const ngx_http_variable_t ngx_http_aws_sigv4_request_vars[] = {

    { ngx_string("aws_sigv4_host"), NULL,
      ngx_http_aws_sigv4_request_variable_handler,
      ngx_http_aws_sigv4_var_host, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("aws_sigv4_uri"), NULL,
      ngx_http_aws_sigv4_request_variable_handler,
      ngx_http_aws_sigv4_var_uri, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("aws_sigv4_x_amz_date"), NULL,
      ngx_http_aws_sigv4_request_variable_handler,
      ngx_http_aws_sigv4_var_x_amz_date, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("aws_sigv4_authorization"), NULL,
      ngx_http_aws_sigv4_request_variable_handler,
      ngx_http_aws_sigv4_var_authorization, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t ngx_http_aws_sigv4_request_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;
    for (v = (ngx_http_variable_t *) ngx_http_aws_sigv4_request_vars; v->name.len; v++)
    {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL)
        {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_aws_sigv4_request_variable_handler(ngx_http_request_t *r,
                                                             ngx_http_variable_value_t *v,
                                                             uintptr_t data)
{
    /* get the module context from the main request because the var will be used by subrequest*/
    ngx_http_aws_sigv4_request_ctx_t *ctx = ngx_http_get_module_ctx(r->main,
                                                                    ngx_http_aws_sigv4_request_module);
    if (ctx == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "aws sigv4 request module is NULL");
        return NGX_ERROR;
    }

    ngx_str_t *var = NULL;
    switch (data)
    {
        case ngx_http_aws_sigv4_var_host:
            var = &ctx->sigv4_host;
            break;
        case ngx_http_aws_sigv4_var_uri:
            var = &ctx->sigv4_uri;
            break;
        case ngx_http_aws_sigv4_var_x_amz_date:
            var = &ctx->sigv4_x_amz_date;
            break;
        case ngx_http_aws_sigv4_var_authorization:
            var = &ctx->sigv4_authorization;
            break;
        default:
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "aws sigv4 request variable %d is not recognized", data);
    }

    if (var != NULL && var->data != NULL)
    {
        v->data         = var->data;
        v->len          = var->len;
        v->valid        = 1;
        v->no_cacheable = 0;
        v->not_found    = 0;
    }
    else
    {
        v->data         = NULL;
        v->len          = 0;
        v->valid        = 0;
        v->no_cacheable = 1;
        v->not_found    = 1;
    }
    return NGX_OK;
}

static void *ngx_http_aws_sigv4_request_create_conf(ngx_conf_t *cf)
{
    ngx_http_aws_sigv4_request_conf_t *lcf;
    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_aws_sigv4_request_conf_t));
    if (lcf == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to allocate memory in conf pool");
    }
    lcf->aws_sigv4_enabled = 0;
    return lcf;
}

static char *ngx_http_aws_access_key_path_set(ngx_conf_t *cf,
                                              ngx_command_t *cmd,
                                              void *conf)
{
    ngx_http_aws_sigv4_request_conf_t *lcf = conf;
    ngx_str_t *cmd_args;
    cmd_args = cf->args->elts;
    if (lcf->access_key_path.data != NULL)
    {
        return "is duplicate";
    }
    lcf->access_key_path  = cmd_args[1];

    char* ret = NGX_CONF_OK;
    /* load aws access key from file */
    if (!lcf->access_key_path.len || !lcf->access_key_path.data)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "empty access key path");
        return NGX_CONF_ERROR;
    }
    ngx_file_t key_file;
    key_file.name   = lcf->access_key_path;
    key_file.log    = cf->log;
    key_file.offset = 0;
    key_file.fd     = ngx_open_file(key_file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (key_file.fd == NGX_INVALID_FILE)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_open_file_n " access key file \"%V\" failed due to invalid file",
                           &(key_file.name));
        return NGX_CONF_ERROR;
    }

    ngx_file_info_t key_file_info;
    if (ngx_fd_info(key_file.fd, &key_file_info) == NGX_FILE_ERROR)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_fd_info_n " access key file \"%V\" failed",
                           &(key_file.name));
        ret = NGX_CONF_ERROR;
        goto cleanup;
    }
    ssize_t size    = ngx_file_size(&key_file_info);
    u_char* key_buf = ngx_pcalloc(cf->pool, size);
    if (key_buf == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to allocate memory in conf pool");
        ret = NGX_CONF_ERROR;
        goto cleanup;
    }
    ssize_t n = ngx_read_file(&key_file, key_buf, size, 0);
    if (n != size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to read access key file \"%V\"",
                           &(key_file.name));
        ret = NGX_CONF_ERROR;
        goto cleanup;
    }
    /* the access key id and secret access key should be separated by newline */
    u_char* nl = ngx_strlchr(key_buf, key_buf + size, '\n');
    lcf->access_key_id.data     = key_buf;
    lcf->access_key_id.len      = nl - key_buf;
    lcf->secret_access_key.data = nl + 1;
    lcf->secret_access_key.len  = (key_buf + size) - (nl + 1);
    /* remove extra newline */
    if (lcf->secret_access_key.data[lcf->secret_access_key.len - 1] == '\n')
    {
        lcf->secret_access_key.len--;
    }
cleanup:
    if (ngx_close_file(key_file.fd) == NGX_FILE_ERROR)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_close_file_n " access key file \"%V\" failed",
                           &(key_file.name));
    }
    return ret;
}

static char *ngx_http_aws_service_set(ngx_conf_t *cf,
                                      ngx_command_t *cmd,
                                      void *conf)
{
    ngx_http_aws_sigv4_request_conf_t *lcf = conf;
    ngx_str_t *cmd_args;
    cmd_args = cf->args->elts;
    ngx_uint_t  i;
    ngx_flag_t has_region = 0, has_name = 0, has_endpoint = 0;
    for (i = 1; i < cf->args->nelts; i++)
    {
        if (ngx_strncmp(cmd_args[i].data, "region=", 7) == 0)
        {
            has_region = 1;
            lcf->aws_region.data  = cmd_args[i].data + 7;
            lcf->aws_region.len   = cmd_args[i].len - 7;
        }
        else if (ngx_strncmp(cmd_args[i].data, "name=", 5) == 0)
        {
            has_name = 1;
            lcf->aws_service_name.data  = cmd_args[i].data + 5;
            lcf->aws_service_name.len   = cmd_args[i].len - 5;
        }
        else if (ngx_strncmp(cmd_args[i].data, "endpoint=", 9) == 0)
        {
            has_endpoint = 1;
            lcf->aws_service_endpoint.data  = cmd_args[i].data + 9;
            lcf->aws_service_endpoint.len   = cmd_args[i].len - 9;
        }
        else
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unsupported argument: %V", &cmd_args[i]);
            return NGX_CONF_ERROR;
        }
    }
    if (!has_region || !has_name || !has_endpoint)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "missing arguments for aws_sigv4 directive");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *ngx_http_aws_sigv4_request_set(ngx_conf_t *cf,
                                            ngx_command_t *cmd,
                                            void *conf)
{
    ngx_http_aws_sigv4_request_conf_t *lcf = conf;
    ngx_str_t *cmd_args;
    cmd_args = cf->args->elts;
    if (lcf->internal_uri.data != NULL)
    {
        return "is duplicate";
    }
    /* aws_access_key_path and aws_service need to be set first */
    if (lcf->access_key_id.data == NULL || lcf->aws_region.data == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "missing aws access key and service configuration");
        return NGX_CONF_ERROR;
    }
    if (ngx_strncmp(cmd_args[1].data, "off", 3) == 0) {
        lcf->internal_uri.len = 0;
        lcf->internal_uri.data = (u_char *) "";
        return NGX_CONF_OK;
    }

    lcf->internal_uri = cmd_args[1];
    lcf->aws_sigv4_enabled = 1;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_aws_sigv4_request_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt         *h = NULL;
    ngx_http_core_main_conf_t   *cmcf = NULL;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL)
    {
        return NGX_ERROR;
    }
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }
    *h = ngx_http_aws_sigv4_request_handler;
    return NGX_OK;
}

static ngx_int_t ngx_http_aws_sigv4_request_handler(ngx_http_request_t *r)
{
    ngx_http_aws_sigv4_request_conf_t *lcf;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_aws_sigv4_request_module);
    if (lcf == NULL)
    {
        return NGX_ERROR;
    }
    if (!lcf->aws_sigv4_enabled)
    {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "aws sigv4 request is not enabled for this location");
        return NGX_DECLINED;
    }
    ngx_http_aws_sigv4_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_aws_sigv4_request_module);
    if (ctx == NULL)
    {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_aws_sigv4_request_ctx_t));
        if (ctx == NULL)
        {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "failed to allocate memory for sigv4 request context");
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_aws_sigv4_request_module);
    }
    return NGX_DECLINED;
}