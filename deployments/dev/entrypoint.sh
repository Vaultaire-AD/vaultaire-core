#!/bin/bash
# Start rsyslog
/usr/sbin/rsyslogd

# Start SSH in foreground
exec /usr/sbin/sshd -D