FROM alpine:3.9
RUN apk upgrade --no-cache && \
  apk --no-cache add openvswitch logrotate
COPY docker/launch-ovs.sh docker/liveness-ovs.sh dist-static/ovsresync /usr/local/bin/
CMD ["/usr/local/bin/launch-ovs.sh"]
