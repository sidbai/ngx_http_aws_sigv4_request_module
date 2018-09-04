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

            proxy_pass https://$aws_sigv4_host;
            proxy_ssl_name $aws_sigv4_host;
        }
    }
}
```

You can also configure to rewrite uri to internal location if you don't want to expose s3 bucket information.
```
http
    server {
        listen       80;

        rewrite ^/my_files/(.*)$ /some_test_s3_bucket/$1 last;

        location /some_test_s3_bucket/ {
            internal;
            resolver 8.8.8.8;
            aws_service region=us-east-1 name=s3 endpoint=s3.amazonaws.com;
            aws_access_key_path /path/to/aws_access_key_file;
            aws_sigv4_request on;

            proxy_pass https://$aws_sigv4_host;
            proxy_ssl_name $aws_sigv4_host;
        }
    }
}
```

Similar config for other service, e.g., CloudWatch
```
http
    server {
        listen       80;

        rewrite ^/my_cw/(.*)$ /$1 last;

        location /doc/2010-08-01/ {
            internal;
            resolver 8.8.8.8;
            aws_service region=us-east-2 name=monitoring endpoint=monitoring.us-east-2.amazonaws.com;
            aws_access_key_path /path/to/aws_access_key_file;
            aws_sigv4_request on;

            proxy_pass https://$aws_sigv4_host;
            proxy_ssl_name $aws_sigv4_host;
        }
    }
}
```

### Test

#### Test S3 Put and Get

```
$ cat /tmp/some_test_file.txt
this is a test file

$ curl -vv http://localhost/my_files/some_test_file.txt --upload-file /tmp/some_test_file.txt
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 80 (#0)
> PUT /my_files/some_test_file.txt HTTP/1.1
> Host: localhost
> User-Agent: curl/7.55.1
> Accept: */*
> Content-Length: 20
> Expect: 100-continue
>
< HTTP/1.1 100 Continue
* We are completely uploaded and fine
< HTTP/1.1 200 OK
< Server: nginx/1.14.0
< Date: Tue, 04 Sep 2018 05:08:16 GMT
< Content-Length: 0
< Connection: keep-alive
< x-amz-id-2: xxxxxxxxxxxxxxxxxxxxxxx
< x-amz-request-id: xxxxxxxxxxxxxxxxxxxxxxx
< ETag: "xxxxxxxxxxxxxxxxxxxxxxx"
<
* Connection #0 to host localhost left intact

$ curl -vv http://localhost/my_files/some_test_file.txt
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 80 (#0)
> GET /my_files/some_test_file.txt HTTP/1.1
> Host: localhost
> User-Agent: curl/7.55.1
> Accept: */*
>
< HTTP/1.1 200 OK
< Server: nginx/1.14.0
< Date: Tue, 04 Sep 2018 05:08:41 GMT
< Content-Type: binary/octet-stream
< Content-Length: 20
< Connection: keep-alive
< x-amz-id-2: xxxxxxxxxxxxxxxxxxxxxxx
< x-amz-request-id: xxxxxxxxxxxxxxxxxxxxxxx
< Last-Modified: Tue, 04 Sep 2018 05:08:17 GMT
< ETag: "xxxxxxxxxxxxxxxxxxxxxxx"
< Accept-Ranges: bytes
<
this is a test file
* Connection #0 to host localhost left intact
```

#### Test CloudWatch PutMetricData API

https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricData.html

```
$ curl -vv "http://localhost/my_cw/doc/2010-08-01/?Action=PutMetricData&Version=2010-08-01&Namespace=TestNamespace&MetricData.member.1.MetricName=buffers&MetricData.member.1.Unit=Bytes&MetricData.member.1.Value=231434333&MetricData.member.1.Dimensions.member.1.Name=InstanceType&MetricData.member.1.Dimensions.member.1.Value=m1.small"
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 80 (#0)
> GET /my_cw/doc/2010-08-01/?Action=PutMetricData&Version=2010-08-01&Namespace=TestNamespace&MetricData.member.1.MetricName=buffers&MetricData.member.1.Unit=Bytes&MetricData.member.1.Value=231434333&MetricData.member.1.Dimensions.member.1.Name=InstanceType&MetricData.member.1.Dimensions.member.1.Value=m1.small HTTP/1.1
> Host: localhost
> User-Agent: curl/7.55.1
> Accept: */*
>
< HTTP/1.1 200 OK
< Server: nginx/1.14.0
< Date: Tue, 04 Sep 2018 04:37:54 GMT
< Content-Type: text/xml
< Content-Length: 212
< Connection: keep-alive
< x-amzn-RequestId: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
<
<PutMetricDataResponse xmlns="http://monitoring.amazonaws.com/doc/2010-08-01/">
  <ResponseMetadata>
    <RequestId>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</RequestId>
  </ResponseMetadata>
</PutMetricDataResponse>
```
