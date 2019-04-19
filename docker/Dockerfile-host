FROM alpine:3.9
RUN apk upgrade --no-cache
COPY dist-static/aci-containers-host-agent dist-static/opflex-agent-cni docker/launch-hostagent.sh /usr/local/bin/
CMD ["/usr/local/bin/launch-hostagent.sh"]
