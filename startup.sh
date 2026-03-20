#! /bin/bash

# Modernize with uv and python 3.12
apt-get update
apt-get -y install cron rsyslog curl

# install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="/root/.local/bin:$PATH"

# install dependencies
cd /opt/alerts
uv sync

/etc/init.d/rsyslog start
/etc/init.d/cron start

if [ -f "/opt/alerts/python.env" ]; then
    echo 'adding env to cron'
    cat /opt/alerts/python.env > /var/spool/cron/crontabs/root
fi

# Use uv run for the cron job
CRONTAB_ENTRIES='
*/15 * * * * cd /opt/alerts; /root/.local/bin/uv run alerta.py 2>&1 | logger
'

cat << EOF >> /var/spool/cron/crontabs/root
${CRONTAB_ENTRIES}
EOF
chmod 0600 /var/spool/cron/crontabs/root

# log cron jobs
cat << EOF >> /etc/default/cron
EXTRA_OPTS='-L 5'
EOF

# make it go
/etc/init.d/rsyslog restart
/etc/init.d/cron restart

tail -f /var/log/syslog /var/log/messages
