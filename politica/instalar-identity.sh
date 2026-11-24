#!/bin/bash
# Instala identity (R1/R2/R3, G05) en ONOS-1 y aaa-agent en ONOS-1 y ONOS-2.
# Se ejecuta desde el Mac, en politica/, con los canales ~/.ssh/ctl-5806 (ONOS-1) y
# ~/.ssh/ctl-5807 (ONOS-2). identity necesita ~/.netrc de ONOS en ONOS-1 (REST 8181).
#   - /opt/g05/politica: identity.py, r2ctl.py, policy.yaml, topology.yaml
#   - /var/lib/r2/sessions.json: sesiones (sobrevive reinicios)
#   - /var/log/g05/incidentes.jsonl: registro de incidentes de R3 (GET /identity/incidents)
set -euo pipefail
GW=10.20.12.7
cd "$(dirname "$0")"
s() { local p=$1; shift; ssh -S ~/.ssh/ctl-$p x@$GW "$@"; }
cp_() { scp -q -o ControlPath=~/.ssh/ctl-$1 "${@:2:$#-2}" x@$GW:"${@: -1}"; }

cp_ 5806 identity.py r2ctl.py ddos.py policy.yaml topology.yaml aaa-agent.py /tmp/
s 5806 'set -e
sudo install -d -o ubuntu -g ubuntu /opt/g05/politica /var/lib/r2 /var/log/g05
for f in identity.py r2ctl.py ddos.py policy.yaml topology.yaml; do sudo install -m 644 -o ubuntu /tmp/$f /opt/g05/politica/$f; done
sudo install -m 755 /tmp/aaa-agent.py /opt/g05/aaa-agent.py
sudo tee /etc/systemd/system/g05-identity.service >/dev/null <<EOF
[Unit]
Description=identity (R1 G05): une 802.1X, rol e IP y programa R2 en ONOS
After=docker.service network-online.target
[Service]
User=ubuntu
Environment=HOME=/home/ubuntu R2_SESSIONS=/var/lib/r2/sessions.json PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/g05/politica/identity.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload; sudo systemctl enable g05-identity >/dev/null 2>&1; sudo systemctl restart g05-identity'

for p in 5806 5807; do
  cp_ $p aaa-agent.py /tmp/
  s $p 'set -e
sudo install -D -m 755 /tmp/aaa-agent.py /opt/g05/aaa-agent.py
sudo tee /etc/systemd/system/g05-aaa-agent.service >/dev/null <<EOF
[Unit]
Description=Agente de eventos AAA (G05): log de ONOS -> identity
After=docker.service
[Service]
ExecStart=/usr/bin/python3 /opt/g05/aaa-agent.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload; sudo systemctl enable g05-aaa-agent >/dev/null 2>&1; sudo systemctl restart g05-aaa-agent
echo "$(hostname): aaa-agent $(systemctl is-active g05-aaa-agent)"'
done
sleep 4
echo "onos-1: identity $(s 5806 'systemctl is-active g05-identity')"
