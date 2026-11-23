#!/bin/bash
# Prepara un servidor del campus para la Fase A de R2 (se ejecuta en la VM, con sudo).
# Uso: servidores.sh <recursos|ldap-radius|dns-dhcp>
# - Direcciones de ens4 (una por recurso) y ruta de vuelta 10.0.0.0/8 por Core-1.
# - Servicios de prueba (svc.py): cada IP responde con un banner que identifica el
#   recurso; así `nc` distingue una conexión permitida de una bloqueada.
set -euo pipefail
rol=$1
case "$rol" in
  recursos)
    addrs="10.100.0.50/28, 10.100.0.66/28, 10.100.0.130/28, 10.100.0.146/28, 10.100.0.162/28, 10.100.0.178/28, 10.100.1.10/25, 10.100.1.150/28, 203.0.113.10/32"
    via=10.100.0.49
    spec='[{"name":"matricula","ip":"10.100.0.50","tcp":[80,443]},
           {"name":"planillas","ip":"10.100.0.66","tcp":[80,443]},
           {"name":"notas","ip":"10.100.0.130","tcp":[80,443]},
           {"name":"investigacion","ip":"10.100.0.146","tcp":[80,443]},
           {"name":"laboratorio","ip":"10.100.0.162","tcp":[80,443]},
           {"name":"admin-unidad","ip":"10.100.0.178","tcp":[80,443]},
           {"name":"portal","ip":"10.100.1.10","tcp":[80,443]},
           {"name":"mesa-ayuda","ip":"10.100.1.150","tcp":[80,443]},
           {"name":"internet","ip":"203.0.113.10","tcp":[80,443]}]' ;;
  ldap-radius)
    addrs="10.100.0.18/28, 10.100.0.34/28"
    via=10.100.0.17
    spec='[{"name":"ldap","ip":"10.100.0.18","tcp":[80,443]},
           {"name":"radius","ip":"10.100.0.34","tcp":[80,443]}]' ;;
  dns-dhcp)
    addrs="10.100.1.130/28"
    via=10.100.1.129
    spec='[{"name":"dns","ip":"10.100.1.130","tcp":[53,80,443],"udp":[53]}]' ;;
  *) echo "rol desconocido: $rol" >&2; exit 1 ;;
esac

cat > /tmp/99-vnrt-ens4.yaml <<EOF
network:
  version: 2
  ethernets:
    ens4:
      renderer: networkd
      optional: true
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
      addresses: [$addrs]
      routes:
        - to: 10.0.0.0/8
          via: $via
        - to: 203.0.113.0/24
          via: $via
EOF
[ "$rol" = recursos ] && sed -i '/203.0.113.0\/24/,+1d' /tmp/99-vnrt-ens4.yaml
sudo install -m 600 /tmp/99-vnrt-ens4.yaml /etc/netplan/99-vnrt-ens4.yaml
rm -f /tmp/99-vnrt-ens4.yaml
sudo netplan apply

sudo mkdir -p /opt/g05
sudo tee /opt/g05/svc.json >/dev/null <<<"$spec"
sudo tee /etc/systemd/system/g05-svc.service >/dev/null <<'EOF'
[Unit]
Description=Servicios de prueba de R2 (G05)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/g05/svc.py /opt/g05/svc.json
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable g05-svc >/dev/null 2>&1
sudo systemctl restart g05-svc
sleep 2
echo "$(hostname): $(systemctl is-active g05-svc), $(sudo ss -Hltnu | grep -c python3) sockets; ruta $(ip -4 route get 10.20.0.10 | head -1)"
