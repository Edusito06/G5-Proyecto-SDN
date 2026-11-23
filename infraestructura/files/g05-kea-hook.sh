#!/bin/sh
# Hook run_script de Kea (G05): avisa a identity de cada concesión DHCP.
# Kea lo llama con el nombre del evento como $1 y los datos en variables de entorno.
IDENTITY=${IDENTITY:-http://192.168.0.16:5001/identity/dhcp}
post() {  # $1 ev, $2 mac, $3 ip
  [ -n "$2" ] && [ -n "$3" ] || return 0
  curl -s -m 3 -o /dev/null -X POST -H 'Content-Type: application/json' \
       -d "{\"ev\": \"$1\", \"mac\": \"$2\", \"ip\": \"$3\"}" "$IDENTITY" || true
}
case "$1" in
  leases4_committed)
    i=0
    while [ "$i" -lt "${LEASES4_SIZE:-0}" ]; do
      eval "ip=\${LEASES4_AT${i}_ADDRESS:-}; mac=\${LEASES4_AT${i}_HWADDR:-}"
      post add "$mac" "$ip"
      i=$((i + 1))
    done ;;
  lease4_release|lease4_expire|lease4_decline)
    post del "${LEASE4_HWADDR:-}" "${LEASE4_ADDRESS:-}" ;;
esac
exit 0
