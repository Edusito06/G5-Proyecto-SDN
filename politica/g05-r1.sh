#!/bin/bash
# Cliente 802.1X (EAP-TLS) de los usuarios de prueba de R1 en la VM Alumno.
# Cada usuario de prueba vive en su namespace (ver usuarios-ns.sh) con una macvlan
# del mismo nombre; wpa_supplicant corre dentro del namespace.
#
#   g05-r1 login  <ns> <usuario> [cert]   autentica (admin01, adm01, doc01, alu01, sing01);
#                                  cert: otro certificado de $PKI (pruebas de accesos inválidos)
#   g05-r1 logout <ns>             EAPOL-Logoff y fin del supplicant
#   g05-r1 status <ns>             estado de la autenticación
#   g05-r1 dhcp   <ns>             pide IP por DHCP dentro del namespace
#
# El VNRT no reenvía la MAC de grupo de EAPOL (01:80:c2:00:00:03): el EAPOL saliente
# se reescribe a broadcast con tc antes de salir de la macvlan.
set -euo pipefail
PKI=/etc/wpa_supplicant/pki
accion=${1:?uso: g05-r1 login|logout|status|dhcp <ns> [usuario]}
ns=${2:?falta el namespace}
run() { ip netns exec "$ns" "$@"; }
case "$accion" in
  login)
    usuario=${3:?falta el usuario}
    cert=${4:-$usuario}
    conf=/etc/wpa_supplicant/r1-$ns.conf
    cat > "$conf" <<EOF
ctrl_interface=/run/wpa_supplicant-$ns
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=TLS
    identity="$usuario"
    ca_cert="$PKI/ca.pem"
    client_cert="$PKI/$cert.pem"
    private_key="$PKI/$cert.key"
    eapol_flags=0
}
EOF
    chmod 600 "$conf"
    run tc qdisc del dev "$ns" clsact 2>/dev/null || true
    run tc qdisc add dev "$ns" clsact
    run tc filter add dev "$ns" egress prio 1 protocol 0x888e flower \
        dst_mac 01:80:c2:00:00:03 action pedit ex munge eth dst set ff:ff:ff:ff:ff:ff pipe
    [ -f "/run/wpa-$ns.pid" ] && kill "$(cat /run/wpa-$ns.pid)" 2>/dev/null && sleep 1 || true
    : > "/tmp/wpa-$ns.log"
    run wpa_supplicant -B -t -D wired -i "$ns" -c "$conf" -P "/run/wpa-$ns.pid" -f "/tmp/wpa-$ns.log"
    # Resultado final: el Access-Reject llega como EAP-Failure después del túnel TLS,
    # así que se espera a que AAA responda y se mira el último evento EAP.
    res="sin respuesta"
    for _ in $(seq 1 25); do
      sleep 1
      ultimo=$(grep -oE 'CTRL-EVENT-EAP-(SUCCESS|FAILURE)' "/tmp/wpa-$ns.log" | tail -1 || true)
      [ -n "$ultimo" ] || continue
      sleep 2
      ultimo=$(grep -oE 'CTRL-EVENT-EAP-(SUCCESS|FAILURE)' "/tmp/wpa-$ns.log" | tail -1)
      [ "$ultimo" = CTRL-EVENT-EAP-SUCCESS ] && res="EAP-Success (supplicant)" || res="EAP-Failure (supplicant)"
      break
    done
    echo "$ns ($usuario): $res"
    # El VNRT puede descartar el EAP-Failure: el acceso real lo decide identity
    # (sin sesión no hay DHCP ni reglas). Compruébalo con `g05-r1 dhcp $ns`.
    ;;
  logout)
    run wpa_cli -p "/run/wpa_supplicant-$ns" -i "$ns" logoff >/dev/null 2>&1 || true
    sleep 1
    [ -f "/run/wpa-$ns.pid" ] && kill "$(cat /run/wpa-$ns.pid)" 2>/dev/null || true
    rm -f "/run/wpa-$ns.pid"
    echo "$ns: sesión cerrada"
    ;;
  status)
    run wpa_cli -p "/run/wpa_supplicant-$ns" -i "$ns" status 2>&1 \
      | grep -E "EAP state|suppPortStatus|selectedMethod|Supplicant PAE|^Failed" || echo "$ns: sin supplicant"
    ;;
  dhcp)
    run ip addr flush dev "$ns"
    run ip route flush dev "$ns" 2>/dev/null || true
    run dhcpcd -x "$ns" >/dev/null 2>&1 || true
    run timeout 40 dhcpcd -1 -4 -q --noipv4ll --nohook resolv.conf -t 30 "$ns" >/dev/null 2>&1 || true
    run ip -4 -br addr show dev "$ns"
    ;;
  *) echo "acción desconocida: $accion" >&2; exit 1 ;;
esac
