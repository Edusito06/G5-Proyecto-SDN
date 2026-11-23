#!/bin/bash
# Levanta (o recrea) el nodo Atomix de esta VM con red de host.
# Uso: atomix-run.sh <atomix-1|atomix-2|atomix-3> <IP de gestión>  (lee la plantilla por stdin)
set -euo pipefail
id=$1; ip=$2
sudo mkdir -p /etc/g05-atomix /var/lib/g05-atomix
sed -e "s/@ID@/$id/" -e "s/@IP@/$ip/" | sudo tee /etc/g05-atomix/atomix.conf >/dev/null
sudo docker rm -f atomix >/dev/null 2>&1 || true
sudo docker run -d --name atomix --restart unless-stopped --network host \
  --log-opt max-size=20m --log-opt max-file=2 \
  -e JAVA_OPTS="-Xms256m -Xmx768m" \
  -v /etc/g05-atomix/atomix.conf:/opt/atomix/conf/atomix.conf:ro \
  -v /var/lib/g05-atomix:/opt/atomix/.data \
  atomix/atomix:3.1.5 --config /opt/atomix/conf/atomix.conf --ignore-resources >/dev/null
echo "$(hostname): contenedor atomix ($id @ $ip:5679) iniciado"
