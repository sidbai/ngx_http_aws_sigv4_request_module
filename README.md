# ngx_http_aws_sigv4_request_module
nginx module to proxy request to AWS service endpoint with sigv4 signing.

### Installation

```
wget http://nginx.org/download/nginx-1.14.0.tar.gz
tar -xzvf nginx-1.14.0.tar.gz
cd nginx-1.14.0/
./configure --with-http_ssl_module --add-module=/path/to/ngx_http_aws_sigv4_request_module/
make
make install
```

### Synopsis

```
http
    server {
        listen       80;

        location /some_test_s3_bucket/ {
            resolver 8.8.8.8;
            aws_service region=us-east-1 name=s3 endpoint=s3.amazonaws.com;
            aws_access_key_path /path/to/aws_access_key_file;
            aws_sigv4_request on;

            proxy_set_header Host $aws_sigv4_host;
            proxy_set_header x-amz-date $aws_sigv4_x_amz_date;
            proxy_set_header Authorization $aws_sigv4_authorization;
            proxy_set_header x-amz-content-sha256 $aws_sigv4_x_amz_content_sha256;
            proxy_pass https://$aws_sigv4_host$aws_sigv4_uri;
            proxy_ssl_name $aws_sigv4_host;
        }
    }
}
```
