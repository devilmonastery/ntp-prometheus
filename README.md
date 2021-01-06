# ntp-prometheus
simple ntp probe for prometheus

## docker build

```
# Build binary statically.
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo .

# Build docker image.
docker build -t ntp-prober -f Dockerfile .

# Try it
docker run -it --log-driver local ntp-prober
```
