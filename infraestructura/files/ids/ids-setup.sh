#!/bin/bash
# Prepara la VM IDS (R3, G05). Se ejecuta en la VM con sudo, con los .deb de Suricata en
# /tmp/debs (la VM no tiene Internet) y g05.rules + ids-agent.py en /tmp/ids.
#  - ids-gre (túnel GRE con el espejo del puerto de usuarios de R-SW1)
#  - Suricata 7 con AF_PACKET en ids-gre, solo las reglas del G05, EVE con alertas y MAC
#  - ids-agent: alertas -> identity (bloqueo en R-SW1 por ONOS)
set -euo pipefail
if ls /tmp/debs/*.deb >/dev/null 2>&1; then
  printf '#!/bin/sh\nexit 101\n' | sudo tee /usr/sbin/policy-rc.d >/dev/null
  sudo chmod 755 /usr/sbin/policy-rc.d
  sudo DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/debs/*.deb >/tmp/dpkg-ids.log 2>&1 || { tail -15 /tmp/dpkg-ids.log; sudo rm -f /usr/sbin/policy-rc.d; exit 1; }
  sudo rm -f /usr/sbin/policy-rc.d
  rm -rf /tmp/debs
fi

# Túnel GRE del espejo (estilo ERSPAN): R-SW1 (192.168.0.13) encapsula las copias del
# puerto de usuarios hacia el IDS por la red de gestión. El VNRT no entrega al IDS las
# tramas unicast ajenas por el enlace directo R-SW1/ens6 -> ens4, pero sí el GRE.
sudo tee /etc/systemd/network/20-g05-ids-gre.netdev >/dev/null <<'EOF'
[NetDev]
Name=ids-gre
Kind=gretap
MTUBytes=1500
[Tunnel]
Local=192.168.0.22
Remote=192.168.0.13
Key=4735
EOF
sudo tee /etc/systemd/network/20-g05-ids-gre.network >/dev/null <<'EOF'
[Match]
Name=ids-gre
[Link]
Promiscuous=yes
[Network]
DHCP=no
LinkLocalAddressing=no
IPv6AcceptRA=no
ConfigureWithoutCarrier=yes
EOF
# ens3 (gestión) lleva el túnel: se agrega a su perfil de networkd generado por Netplan.
sudo mkdir -p /etc/systemd/network/10-netplan-ens3.network.d
printf '[Network]\nTunnel=ids-gre\n' | sudo tee /etc/systemd/network/10-netplan-ens3.network.d/g05-gre.conf >/dev/null
sudo ip link del ids-gre 2>/dev/null || true
sudo networkctl reload
sudo networkctl reconfigure ens3
sleep 2
sudo ip link set ids-gre up promisc on

# Configuración local de Suricata (incluida desde suricata.yaml).
sudo install -m 644 /tmp/ids/g05.rules /etc/suricata/rules/g05.rules
sudo tee /etc/suricata/g05.yaml >/dev/null <<'EOF'
%YAML 1.1
---
vars:
  address-groups:
    USUARIOS: "[10.10.0.0/24,10.20.0.0/24,10.30.0.0/24,10.40.0.0/24,10.50.0.0/24,10.90.0.0/24]"
    SERVIDORES: "[10.100.0.0/23,203.0.113.0/24]"
    HOME_NET: "[10.0.0.0/8,203.0.113.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
default-rule-path: /etc/suricata/rules
rule-files:
  - g05.rules
af-packet:
  - interface: ids-gre
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      ethernet: yes
      types:
        - alert:
            tagged-packets: no
        - stats:
            totals: yes
            threads: no
            deltas: yes
stats:
  enabled: yes
  interval: 30
EOF
# suricata.yaml del paquete + nuestras definiciones (las nuestras ganan por ir después).
if ! sudo grep -q '^include: g05.yaml' /etc/suricata/suricata.yaml; then
  echo 'include: g05.yaml' | sudo tee -a /etc/suricata/suricata.yaml >/dev/null
fi
sudo sed -i 's/^\(\s*\)- suricata.rules$/\1# - suricata.rules  (G05: sin reglas de Internet)/' /etc/suricata/suricata.yaml
sudo sed -i 's/^LISTENMODE=.*/LISTENMODE=af-packet/; s/^IFACE=.*/IFACE=ids-gre/' /etc/default/suricata 2>/dev/null || true
sudo suricata -T -c /etc/suricata/suricata.yaml >/tmp/suricata-test.log 2>&1 || { tail -15 /tmp/suricata-test.log; exit 1; }
sudo systemctl enable suricata >/dev/null 2>&1
sudo systemctl restart suricata

# Agente de alertas.
sudo install -D -m 755 /tmp/ids/ids-agent.py /opt/g05/ids-agent.py
sudo tee /etc/systemd/system/g05-ids-agent.service >/dev/null <<'EOF'
[Unit]
Description=Agente de alertas del IDS (R3 G05): eve.json -> identity
After=suricata.service network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/g05/ids-agent.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now g05-ids-agent >/dev/null 2>&1
sleep 5
echo "suricata: $(systemctl is-active suricata)  agente: $(systemctl is-active g05-ids-agent)"
sudo grep -oE "[0-9]+ rules successfully loaded|[0-9]+ signatures processed" /var/log/suricata/suricata.log | tail -1 || true
