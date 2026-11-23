#!/bin/bash
# Levanta el nodo ONOS de esta VM en modo clúster (red de host, almacenamiento en Atomix).
# OpenFlow NO se activa aquí: primero se configuran allowExtraneousRules/Groups y la app
# in-band, y recién después se activa org.onosproject.openflow (ver onos-configurar.sh).
# Uso: onos-run.sh <IP de gestión>   (lee la plantilla de cluster.json por stdin)
set -euo pipefail
ip=$1
sudo mkdir -p /etc/g05-onos
sed -e "s/@IP@/$ip/g" | sudo tee /etc/g05-onos/cluster.json >/dev/null
if sudo docker ps -a --format '{{.Names}}' | grep -qx onos; then
  if [ "$(sudo docker inspect onos --format '{{.HostConfig.NetworkMode}}')" != host ]; then
    sudo docker stop onos >/dev/null
    sudo docker rename onos onos-standalone   # se conserva para volver atrás
    sudo docker update --restart no onos-standalone >/dev/null
  else
    sudo docker rm -f onos >/dev/null
  fi
fi
sudo docker run -d --name onos --restart unless-stopped --network host \
  --log-opt max-size=50m --log-opt max-file=2 \
  -e ONOS_APPS=drivers \
  -v /etc/g05-onos/cluster.json:/root/onos/config/cluster.json:ro \
  onosproject/onos:2.7.0 >/dev/null
echo "$(hostname): ONOS en modo clúster iniciado (nodo $ip)"
