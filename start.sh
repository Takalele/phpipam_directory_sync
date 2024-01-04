#!/bin/sh
set -e
exec /sbin/tini -s -- /bin/sh -c /usr/sbin/crond &
exec /sbin/tini -s -- /bin/sh -c /start_apache2
