# Simple proxy tests

Usage:

```bash
./<test> --help
```

## Params

- `--port` - port that local proxy is listening on. Default: 8080.
- `--url` - url to access through proxy. Default: 'http://xcal1.vodafone.co.uk/10MB.zip'.
- `--requests` - number of requests. Default: 10.
- `--timeout` - curl timeout (see `curl --max-time`). Default: 10.
- `--concurrency` - number of parallel requests if available for test. Default: 10.

## Dependencies

Basic calculator:

```bash
sudo apt install bc
```

## Examples

```bash
./1-sequential.sh --port 9000 --url http://xcal1.vodafone.co.uk/5MB.zip --requests 10 --timeout 60
```
```bash
./2-concurrent-batches.sh --port 9000 --url http://xcal1.vodafone.co.uk/5MB.zip --requests 50 --timeout 10 --concurrency 20
```
```bash
./3-cache-invalidation.sh --port 9000 --url http://xcal1.vodafone.co.uk/5MB.zip --requests 10 --timeout 10
```
```bash
./4-parallel-clients.sh --port 9000 --url http://xcal1.vodafone.co.uk/5MB.zip --requests 500 --timeout 10
```
```bash
./5-incremental-interrupt.sh --port 9000 --url http://xcal1.vodafone.co.uk/50MB.zip --requests 30 --timeout 60
```

## Local nginx with caching

1. Cache folder:

```bash
sudo mkdir -p /tmp/cache/nginx
sudo chmod -R 777 /tmp/cache/nginx
```

2. Write to `/etc/nginx/conf.d/caching_proxy.conf`:

```conf
proxy_cache_path /tmp/cache/nginx levels=1:2 keys_zone=http_cache:10m
                    max_size=10g inactive=60m use_temp_path=off;

resolver 8.8.8.8 1.1.1.1 valid=300s;
resolver_timeout 5s;

server {
    listen 9001;

    access_log /var/log/nginx/caching_proxy_access.log;
    error_log /var/log/nginx/caching_proxy_error.log;

    location / {
        proxy_pass http://$http_host$uri$is_args$args;

        proxy_http_version 1.0;
        proxy_set_header Connection "close";

        proxy_cache http_cache;
        proxy_cache_valid 5s; # Cache ttl = 5 seconds

        # Cache partial data
        proxy_cache_revalidate on;
        proxy_cache_lock on;
        proxy_cache_lock_timeout 5s;
        proxy_cache_lock_age 5s;

        proxy_cache_key "$scheme$host$request_uri$is_args$args";
    }
}
```

3. Check config:

```bash
sudo nginx -t
```

4. Restart nginx:

```bash
sudo nginx -s reload
```

5. Run tests:

```bash
/1-sequential.sh --port 9001 --url http://xcal1.vodafone.co.uk/5MB.zip --requests 10 --timeout 60
```
