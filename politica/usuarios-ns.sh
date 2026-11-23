#!/bin/bash
# Crea (o recrea) los usuarios de prueba de R2 en la VM Alumno: un namespace por
# usuario con una macvlan sobre ens4 (MAC propia, llega a R-SW1/ens7), su IP fija
# y la ruta por defecto hacia el gateway de su rol en Core-1 (10.<rol*10>.0.1).
# Uso (en la VM Alumno):  sudo bash usuarios-ns.sh [crear|borrar]
set -euo pipefail
accion=${1:-crear}
# nombre  MAC                 IP/máscara      gateway
USUARIOS="
u-inv 02:05:00:00:00:01 10.10.0.10/24 10.10.0.1
u-alu 02:05:00:00:00:02 10.20.0.10/24 10.20.0.1
u-doc 02:05:00:00:00:03 10.30.0.10/24 10.30.0.1
u-adm 02:05:00:00:00:04 10.40.0.10/24 10.40.0.1
u-net 02:05:00:00:00:05 10.50.0.10/24 10.50.0.1
u-cic 02:05:00:00:00:09 10.90.0.20/24 10.90.0.1
"
echo "$USUARIOS" | while read -r ns mac ip gw; do
  [ -z "$ns" ] && continue
  ip netns del "$ns" 2>/dev/null || true
  [ "$accion" = borrar ] && continue
  ip netns add "$ns"
  ip link add link ens4 name "$ns" address "$mac" type macvlan mode bridge
  ip link set "$ns" netns "$ns"
  ip -n "$ns" link set lo up
  ip -n "$ns" link set "$ns" up
  ip -n "$ns" addr add "$ip" dev "$ns"
  ip -n "$ns" route add default via "$gw" dev "$ns"
  echo "$ns: $mac $ip -> $gw"
done
