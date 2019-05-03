FROM alpine:3.9
RUN apk upgrade --no-cache
COPY dist-static/aci-containers-controller /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/aci-containers-controller", "-config-path", "/usr/local/etc/aci-containers/controller.conf"]
