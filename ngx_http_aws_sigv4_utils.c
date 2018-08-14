#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "ngx_http_aws_sigv4_utils.h"

#define AWS_SIGV4_AUTH_HEADER_NAME            "Authorization"
#define AWS_SIGV4_SIGNING_ALGORITHM           "AWS4-HMAC-SHA256"
#define AWS_SIGV4_UNSIGNED_PAYLOAD_OPTION     "UNSIGNED-PAYLOAD"
#define AWS_SIGV4_HEX_SHA256_LENGTH           SHA256_DIGEST_LENGTH * 2
#define AWS_SIGV4_AUTH_HEADER_MAX_LEN         1024
#define AWS_SIGV4_CANONICAL_REQUEST_BUF_LEN   1024
#define AWS_SIGV4_STRING_TO_SIGN_BUF_LEN      1024
#define AWS_SIGV4_KEY_BUF_LEN                 33
#define AWS_SIGV4_MAX_NUM_QUERY_COMPONENTS    50

typedef int (*aws_sigv4_compar_func_t)(const void*, const void*);

static inline int aws_sigv4_empty_str(ngx_str_t* str)
{
    return (str == NULL || str->data == NULL || str->len == 0) ? 1 : 0;
}

static int aws_sigv4_strcmp(ngx_str_t* str1, ngx_str_t* str2)
{
    size_t len = str1->len <= str2->len ? str1->len : str2->len;
    return strncmp((char*) str1->data, (char*) str2->data, len);
}

static inline void parse_query_components(ngx_str_t*  query_str,
                                          ngx_str_t*  query_component_arr,
                                          size_t*     arr_len)
{
    if (aws_sigv4_empty_str(query_str)
        || query_component_arr == NULL)
    {
        arr_len = 0;
        return;
    }
    size_t idx = 0;
    unsigned char* c_ptr = query_str->data;
    query_component_arr[0].data = c_ptr;
    while (c_ptr != query_str->data + query_str->len)
    {
        if (*c_ptr == '&')
        {
            query_component_arr[idx].len = c_ptr - query_component_arr[idx].data;
            query_component_arr[++idx].data = ++c_ptr;
        }
        else
        {
            c_ptr++;
        }
    }
    query_component_arr[idx].len = c_ptr - query_component_arr[idx].data;
    *arr_len = idx + 1;
}

static void get_hexdigest(ngx_str_t* str_in, ngx_str_t* hex_out)
{
    static const unsigned char digits[] = "0123456789abcdef";
    unsigned char* c_ptr = hex_out->data;
    for (size_t i = 0; i < str_in->len; i++)
    {
        *(c_ptr++) = digits[(str_in->data[i] & 0xf0) >> 4];
        *(c_ptr++) = digits[str_in->data[i] & 0x0f];
    }
    hex_out->len = str_in->len * 2;
}

static void get_hex_sha256(ngx_str_t* str_in, ngx_str_t* hex_sha256_out)
{
    unsigned char sha256_buf[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, str_in->data, str_in->len);
    SHA256_Final(sha256_buf, &ctx);

    ngx_str_t sha256_str = { .data = sha256_buf, .len = SHA256_DIGEST_LENGTH };
    get_hexdigest(&sha256_str, hex_sha256_out);
}

static void get_signing_key(aws_sigv4_params_t* sigv4_params, ngx_str_t* signing_key)
{
    unsigned char key_buf[AWS_SIGV4_KEY_BUF_LEN]  = { 0 };
    unsigned char msg_buf[AWS_SIGV4_KEY_BUF_LEN]  = { 0 };
    ngx_str_t key = { .data = key_buf };
    ngx_str_t msg = { .data = msg_buf };
    /* kDate = HMAC("AWS4" + kSecret, Date) */
    key.len = ngx_sprintf(key_buf, "AWS4%V", &sigv4_params->secret_access_key) - key_buf;
    /* data in YYYYMMDD format */
    msg.len = ngx_snprintf(msg_buf, 8, "%V", &sigv4_params->x_amz_date) - msg_buf;
    /* get HMAC SHA256 */
    HMAC(EVP_sha256(), key.data, key.len, msg.data, msg.len,
         signing_key->data, (unsigned int *) &signing_key->len);
    /* kRegion = HMAC(kDate, Region) */
    key.len = ngx_sprintf(key_buf, "%V", signing_key) - key_buf;
    msg.len = ngx_sprintf(msg_buf, "%V", &sigv4_params->region) - msg_buf;
    HMAC(EVP_sha256(), key.data, key.len, msg.data, msg.len,
         signing_key->data, (unsigned int *) &signing_key->len);
    /* kService = HMAC(kRegion, Service) */
    key.len = ngx_sprintf(key_buf, "%V", signing_key) - key_buf;
    msg.len = ngx_sprintf(msg_buf, "%V", &sigv4_params->service) - msg_buf;
    HMAC(EVP_sha256(), key.data, key.len, msg.data, msg.len,
         signing_key->data, (unsigned int *) &signing_key->len);
    /* kSigning = HMAC(kService, "aws4_request") */
    key.len = ngx_sprintf(key_buf, "%V", signing_key) - key_buf;
    msg.len = ngx_sprintf(msg_buf, "aws4_request") - msg_buf;
    HMAC(EVP_sha256(), key.data, key.len, msg.data, msg.len,
         signing_key->data, (unsigned int *) &signing_key->len);
}

static void get_credential_scope(aws_sigv4_params_t* sigv4_params,
                                 ngx_str_t* credential_scope)
{
    unsigned char* str = credential_scope->data;
    /* get date in yyyymmdd format */
    str = ngx_snprintf(str, 8, "%V", &sigv4_params->x_amz_date);
    str = ngx_sprintf(str, "/%V/%V/aws4_request",
                      &sigv4_params->region, &sigv4_params->service);
    credential_scope->len = str - credential_scope->data;
}

static void get_signed_headers(aws_sigv4_params_t* sigv4_params,
                               ngx_str_t* signed_headers)
{
    /* TODO: Need to support additional headers and header sorting */
    signed_headers->len = ngx_sprintf(signed_headers->data, "host;x-amz-date")
                          - signed_headers->data;
}

static void get_canonical_headers(aws_sigv4_params_t* sigv4_params,
                                  ngx_str_t* canonical_headers)
{
    /* TODO: Add logic to remove leading and trailing spaces for header values */
    canonical_headers->len = ngx_sprintf(canonical_headers->data,
                                         "host:%V\nx-amz-date:%V\n",
                                         &sigv4_params->host,
                                         &sigv4_params->x_amz_date)
                             - canonical_headers->data;
}

static void get_canonical_request(aws_sigv4_params_t* sigv4_params,
                                  ngx_str_t* canonical_request)
{
    unsigned char* str = canonical_request->data;
    /* TODO: Here we assume the URI and query string have already been encoded.
     *       Add encoding logic in future.
     */
    str = ngx_sprintf(str, "%V\n%V\n",
                      &sigv4_params->method,
                      &sigv4_params->uri);

    /* query string can be empty */
    if (!aws_sigv4_empty_str(&sigv4_params->query_str))
    {
        ngx_str_t query_components[AWS_SIGV4_MAX_NUM_QUERY_COMPONENTS];
        size_t query_num = 0;
        parse_query_components(&sigv4_params->query_str, query_components, &query_num);
        qsort(query_components, query_num, sizeof(ngx_str_t),
              (aws_sigv4_compar_func_t) aws_sigv4_strcmp);
        for (size_t i = 0; i < query_num; i++)
        {
            str = ngx_sprintf(str, "%V", &query_components[i]);
            if (i != query_num - 1)
            {
                *(str++) = '&';
            }
        }
    }
    *(str++) = '\n';

    ngx_str_t canonical_headers = { .data = str };
    get_canonical_headers(sigv4_params, &canonical_headers);
    str += canonical_headers.len;
    *(str++) = '\n';

    ngx_str_t signed_headers = { .data = str };
    get_signed_headers(sigv4_params, &signed_headers);
    str += signed_headers.len;
    *(str++) = '\n';

    // disable payload signing for now
    /*
    ngx_str_t hex_sha256 = { .data = str };
    get_hex_sha256(&sigv4_params->payload, &hex_sha256);
    str += hex_sha256.len;
    */

    /* TODO: make payload signing option flexible */
    size_t option_len   = strlen(AWS_SIGV4_UNSIGNED_PAYLOAD_OPTION);
    strncpy((char*) str, AWS_SIGV4_UNSIGNED_PAYLOAD_OPTION, option_len + 1);
    str += option_len;

    canonical_request->len = str - canonical_request->data;
}

static void get_string_to_sign(ngx_str_t* request_date,
                               ngx_str_t* credential_scope,
                               ngx_str_t* canonical_request,
                               ngx_str_t* string_to_sign)
{
    unsigned char* str = string_to_sign->data;
    str =  ngx_sprintf(str, "AWS4-HMAC-SHA256\n%V\n%V\n",
                       request_date, credential_scope);

    ngx_str_t hex_sha256 = { .data = str };
    get_hex_sha256(canonical_request, &hex_sha256);
    str += hex_sha256.len;

    string_to_sign->len = str - string_to_sign->data;
}

int aws_sigv4_sign(ngx_http_request_t* req,
                   aws_sigv4_params_t* sigv4_params,
                   aws_sigv4_header_t* auth_header)
{
    if (auth_header == NULL
        || sigv4_params == NULL
        || aws_sigv4_empty_str(&sigv4_params->secret_access_key)
        || aws_sigv4_empty_str(&sigv4_params->access_key_id)
        || aws_sigv4_empty_str(&sigv4_params->method)
        || aws_sigv4_empty_str(&sigv4_params->uri)
        || aws_sigv4_empty_str(&sigv4_params->host)
        || aws_sigv4_empty_str(&sigv4_params->x_amz_date)
        || aws_sigv4_empty_str(&sigv4_params->region)
        || aws_sigv4_empty_str(&sigv4_params->service))
    {
        ngx_log_error(NGX_LOG_EMERG, req->connection->log, 0,
                      "invalid input for func: %s", __func__);
        return AWS_SIGV4_INVALID_INPUT_ERROR;
    }

    auth_header->value.data = ngx_pcalloc(req->pool,
                                          AWS_SIGV4_AUTH_HEADER_MAX_LEN * sizeof(unsigned char));
    if (auth_header->value.data == NULL)
    {
        ngx_log_error(NGX_LOG_EMERG, req->connection->log, 0,
                      "failed to allocate memory for authorization header value in request pool");
        return AWS_SIGV4_MEMORY_ALLOCATION_ERROR;
    }

    auth_header->name.data  = (unsigned char*) AWS_SIGV4_AUTH_HEADER_NAME;
    auth_header->name.len   = strlen(AWS_SIGV4_AUTH_HEADER_NAME);

    /* AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/<credential_scope> */
    unsigned char* str = auth_header->value.data;
    str =  ngx_sprintf(str, "AWS4-HMAC-SHA256 Credential=%V/",
                       &sigv4_params->access_key_id);

    ngx_str_t credential_scope = { .data = str };
    get_credential_scope(sigv4_params, &credential_scope);
    str += credential_scope.len;

    /* SignedHeaders=<signed_headers> */
    str = ngx_sprintf(str, ", SignedHeaders=", &sigv4_params->access_key_id);
    ngx_str_t signed_headers = { .data = str };
    get_signed_headers(sigv4_params, &signed_headers);
    str += signed_headers.len;

    /* Signature=<signature> */
    str = ngx_sprintf(str, ", Signature=", &sigv4_params->access_key_id);
    /* Task 1: Create a canonical request */
    unsigned char canonical_request_buf[AWS_SIGV4_CANONICAL_REQUEST_BUF_LEN]  = { 0 };
    ngx_str_t canonical_request = { .data = canonical_request_buf };
    get_canonical_request(sigv4_params, &canonical_request);
    ngx_log_error(NGX_LOG_DEBUG, req->connection->log, 0,
                  "canonical request: %V", &canonical_request);
    /* Task 2: Create a string to sign */
    unsigned char string_to_sign_buf[AWS_SIGV4_STRING_TO_SIGN_BUF_LEN]  = { 0 };
    ngx_str_t string_to_sign = { .data = string_to_sign_buf };
    get_string_to_sign(&sigv4_params->x_amz_date, &credential_scope,
                       &canonical_request, &string_to_sign);
    ngx_log_error(NGX_LOG_DEBUG, req->connection->log, 0,
                  "string to sign: %V", &string_to_sign);
    /* Task 3: Calculate the signature */
    /* 3.1: Derive signing key if cached signing is invalid */
    if (sigv4_params->cached_signing_key == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                      "null cached signing key ptr");
        return AWS_SIGV4_INVALID_INPUT_ERROR;
    }
    /* cached signing key is no longer valid */
    if (sigv4_params->cached_signing_key->len == 0
        || ngx_strncmp(sigv4_params->cached_date_yyyymmdd->data,
                       sigv4_params->x_amz_date.data, 8) != 0)
    {
        get_signing_key(sigv4_params, sigv4_params->cached_signing_key);
        strncpy((char*) sigv4_params->cached_date_yyyymmdd->data,
                (char*) sigv4_params->x_amz_date.data, 9);
        sigv4_params->cached_date_yyyymmdd->len = 8;
    }
    /* 3.2: Calculate signature on the string to sign */
    unsigned char signed_msg_buf[HMAC_MAX_MD_CBLOCK] = { 0 };
    ngx_str_t signed_msg = { .data = signed_msg_buf };
    /* get HMAC SHA256 */
    HMAC(EVP_sha256(),
         sigv4_params->cached_signing_key->data, sigv4_params->cached_signing_key->len,
         string_to_sign.data, string_to_sign.len,
         signed_msg.data, (unsigned int*) &signed_msg.len);
    ngx_str_t signature = { .data = str };
    get_hexdigest(&signed_msg, &signature);
    str += signature.len;
    auth_header->value.len = str - auth_header->value.data;
    return AWS_SIGV4_OK;
}
