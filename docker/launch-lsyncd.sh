#!/bin/sh

set -e
set -x

echo "Creating directories"
mkdir -p /var/log/
mkdir -p /usr/local/var/lib/opflex-agent-ovs/
mkdir -p /usr/local/etc/opflex-agent-ovs
mkdir -p /etc/lsyncd/
mkdir -p /var/log/lsyncd
touch /var/log/lsyncd.log
touch /var/log/lsyncd-status.log

echo "opflex" >> /etc/rsync.pwd
chmod 600 /etc/rsync.pwd

user=$(echo |cat /etc/configmap/lsyncd.json | awk '/dpuUser/ {print $2}' | tr -d '",:')
ip=$(echo | grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' /etc/configmap/lsyncd.json)

echo "$user@$ip::libopflex"

cat <<EOF > /etc/lsyncd/lsyncd.conf.lua
 settings {
    logfile = "/var/log/lsyncd.log",
    nodaemon = false,
    statusFile = "/var/log/lsyncd-status.log",
 }

 sync {
   default.rsync,
   source = "/usr/local/var/lib/opflex-agent-ovs/",
   target = "$user@$ip::libopflex",
   delay  = 1,
   rsync = {
        _extra = { "--password-file=/etc/rsync.pwd" },
   }
}

sync {
   default.rsync,
   source = "/usr/local/etc/opflex-agent-ovs",
   target = "$user@$ip::etcopflex",
   delay  = 1,
   rsync = {
        _extra = { "--password-file=/etc/rsync.pwd" },
   }
}

EOF

lsyncd /etc/lsyncd/lsyncd.conf.lua

tail -n+1 -F \
	/var/log/lsyncd-status.log \
	/var/log/lsyncd.log
