#!/bin/bash
# Métricas de R1 (G05). Se ejecuta desde el Mac con los canales ~/.ssh/ctl-<puerto>
# (5806 ONOS-1, 5809 ldap-radius, 5813 Alumno). Compatible con bash 3.2.
#
#   bash pruebas/prueba-r1.sh invalidos [repeticiones]  % de accesos inválidos bloqueados
#   bash pruebas/prueba-r1.sh latencia  [n]             latencia completa de autenticación
#   bash pruebas/prueba-r1.sh carga     [niveles...]    autenticaciones EAP-TLS/s en RADIUS
#
# Un acceso inválido cuenta como bloqueado si, después del intento y del DHCP, no hay
# sesión en identity para esa MAC y el equipo no llega a ningún recurso (ni siquiera a
# los de invitado). Los certificados inválidos los genera certs-pruebas en ldap-radius.
GW=10.20.12.7
NS=u-alu; MAC=02:05:00:00:00:02
alumno() { ssh -S ~/.ssh/ctl-5813 x@$GW "$@"; }
onos1() { ssh -S ~/.ssh/ctl-5806 x@$GW "$@"; }
radius() { ssh -S ~/.ssh/ctl-5809 x@$GW "$@"; }

limpiar() {
  alumno 'for ns in u-inv u-alu u-doc u-adm u-net u-cic; do sudo g05-r1 logout $ns >/dev/null; sudo ip netns exec $ns ip -4 addr flush dev $ns; done'
  for m in 01 02 03 04 05 06; do onos1 "curl -s -X DELETE http://127.0.0.1:5001/identity/sessions/02:05:00:00:00:$m" >/dev/null; done
  sleep 3
}

# Alcance desde un namespace: Mesa de ayuda (invitado), DNS y Portal. Imprime "a/3".
alcance() {
  alumno "sudo ip netns exec $1 bash -c 'n=0; timeout 2 nc -z -w1 10.100.1.150 80 && n=\$((n+1)); \
    timeout 2 nc -z -w1 10.100.1.130 53 && n=\$((n+1)); timeout 2 nc -z -w1 10.100.1.10 443 && n=\$((n+1)); echo \$n' 2>/dev/null"
}
sesion() { onos1 "curl -s http://127.0.0.1:5001/identity/sessions" | grep -c "\"$1\"" ; }

invalidos() {
  REP=${1:-3}
  echo "== Accesos inválidos ($REP repeticiones por caso de 802.1X)"
  printf "%-44s %-26s %-7s %-8s %-9s %s\n" caso supplicant sesion alcance resultado "motivo (radius.log)"
  total=0; bloq=0
  caso() {  # $1 nombre, $2 comando en Alumno, $3 ns a evaluar, $4 mac
    limpiar
    marca=$(radius 'sudo wc -l < /var/log/freeradius/radius.log')
    sup=$(alumno "$2" 2>/dev/null | tail -1 | sed 's/^[^:]*: //')
    alumno "sudo g05-r1 dhcp $3 >/dev/null 2>&1"
    se=$(sesion "$4"); al=$(alcance "$3")
    mot=$(radius "sudo tail -n +$((marca + 1)) /var/log/freeradius/radius.log | grep -E 'Login (incorrect|OK)' | tail -1 | sed -E 's/.*Login (incorrect|OK) ?//' | cut -c1-70")
    total=$((total + 1))
    if [ "$se" = 0 ] && [ "$al" = 0 ]; then r=BLOQUEADO; bloq=$((bloq + 1)); else r=PERMITIDO; fi
    printf "%-44s %-26s %-7s %-8s %-9s %s\n" "$1" "${sup:0:26}" "$se" "$al/3" "$r" "${mot:--}"
  }
  for i in $(seq 1 "$REP"); do
    caso "Usuario válido sin grupo de red (sing01)"    "sudo g05-r1 login $NS sing01"                 $NS $MAC
    caso "Usuario inexistente en LDAP (fantasma01)"    "sudo g05-r1 login $NS fantasma01"             $NS $MAC
    caso "Certificado caducado (alu01)"                "sudo g05-r1 login $NS alu01 alu01-caducado"   $NS $MAC
    caso "Certificado revocado por CRL (alu01)"        "sudo g05-r1 login $NS alu01 alu01-revocado"   $NS $MAC
    caso "Certificado de una CA ajena (alu01)"         "sudo g05-r1 login $NS alu01 alu01-ajena"      $NS $MAC
    caso "Suplantación: identidad admin01, cert alu01" "sudo g05-r1 login $NS admin01 alu01"          $NS $MAC
  done
  caso "Sin 802.1X: solo DHCP"                         "echo -: sin supplicant"                       $NS $MAC
  caso "IP estática sin autenticar (10.20.0.150)"      "sudo ip netns exec u-doc ip addr add 10.20.0.150/24 dev u-doc; sudo ip netns exec u-doc ip route add default via 10.20.0.1; echo -: IP estática" u-doc 02:05:00:00:00:03
  # IP de un usuario autenticado usada desde otro equipo: alu01 autenticado en u-alu y
  # u-doc (sin autenticar) toma su misma IP.
  limpiar
  alumno "sudo g05-r1 login $NS alu01 >/dev/null; sleep 2; sudo g05-r1 dhcp $NS >/dev/null"
  # Precondición: la víctima debe tener acceso antes del conflicto (reglas ya instaladas).
  for k in 1 2 3 4 5 6 7 8 9 10; do [ "$(alcance $NS)" = 3 ] && break; sleep 2; done
  antes=$(alcance $NS)
  ip=$(alumno "sudo ip netns exec $NS ip -4 -o addr show dev $NS | awk '{print \$4}' | cut -d/ -f1")
  alumno "sudo ip netns exec u-doc ip addr add $ip/24 dev u-doc; sudo ip netns exec u-doc ip route add default via 10.20.0.1" 2>/dev/null
  se=$(sesion 02:05:00:00:00:03); al=$(alcance u-doc); total=$((total + 1))
  if [ "$se" = 0 ] && [ "$al" = 0 ]; then r=BLOQUEADO; bloq=$((bloq + 1)); else r=PERMITIDO; fi
  printf "%-44s %-26s %-7s %-8s %-9s %s\n" "IP de alu01 ($ip) desde otro equipo" "-" "$se" "$al/3" "$r" "T1 anti-spoofing (MAC+IP+puerto)"
  echo "  control: alu01 legítimo -> alcance antes del conflicto $antes/3, durante $(alcance $NS)/3"
  limpiar
  echo; echo "  Bloqueados: $bloq/$total ($((100 * bloq / total)) %)"
  echo "  Intentos fallidos registrados en radius.log (última hora): $(radius "sudo grep -c 'Login incorrect' /var/log/freeradius/radius.log")"
  echo "  Rechazos registrados en identity (última hora): $(onos1 "sudo journalctl -u g05-identity --since '-60min' --no-pager | grep -cE 'SESION_RECHAZADA|ACCESO_DENEGADO|DHCP_SIN_SESION'")"
}

latencia() {
  N=${1:-12}
  echo "== Latencia de autenticación ($N logins válidos, reloj de la VM Alumno)"
  echo "   inicio -> EAP-Started -> EAP-Success -> IP por DHCP -> primer acceso permitido (Portal)"
  printf "%-8s %-8s %-11s %-11s %-9s %-11s %-9s\n" n usuario eap_ms tls_ms dhcp_ms acceso_ms total_ms
  set -- alu01 doc01 adm01 admin01
  usuarios="$*"; i=0; RES=""
  while [ $i -lt "$N" ]; do
    u=$(echo $usuarios | awk -v k=$((i % 4 + 1)) '{print $k}')
    limpiar
    r=$(alumno "sudo bash -s" <<EOF
ns=$NS; log=/tmp/wpa-\$ns.log
rm -f \$log
( g05-r1 login \$ns $u >/dev/null 2>&1 & )
for k in \$(seq 1 300); do grep -q CTRL-EVENT-EAP-SUCCESS \$log 2>/dev/null && break; sleep 0.05; done
ini=\$(head -1 \$log | cut -d: -f1); st=\$(grep -m1 EAP-STARTED \$log | cut -d: -f1); ok=\$(grep -m1 EAP-SUCCESS \$log | cut -d: -f1)
td=\$(date +%s.%N)
ip netns exec \$ns dhcpcd -1 -4 -q --noipv4ll --nohook resolv.conf -t 30 \$ns >/dev/null 2>&1
ti=\$(date +%s.%N)
for k in \$(seq 1 200); do timeout 1 ip netns exec \$ns nc -z -w1 10.100.1.10 443 2>/dev/null && break; sleep 0.05; done
ta=\$(date +%s.%N)
awk -v ini=\$ini -v st=\$st -v ok=\$ok -v td=\$td -v ti=\$ti -v ta=\$ta 'BEGIN{printf "%d %d %d %d %d", (ok-ini)*1000, (ok-st)*1000, (ti-td)*1000, (ta-ti)*1000, (ta-ini)*1000}'
EOF
)
    i=$((i + 1))
    set -- $r
    printf "%-8s %-8s %-11s %-11s %-9s %-11s %-9s\n" $i $u $1 $2 $3 $4 $5
    RES="$RES
$r"
  done
  limpiar
  echo "$RES" | sed '/^$/d' | python3 -c '
import statistics as st, sys
cols = ["inicio->EAP-Success", "EAP-Started->Success (TLS)", "DHCP", "IP->primer acceso", "total"]
rows = [list(map(int, l.split())) for l in sys.stdin if l.strip()]
print()
for i, c in enumerate(cols):
    v = sorted(r[i] for r in rows)
    p95 = v[min(len(v) - 1, int(round(0.95 * (len(v) - 1))))]
    print(f"  {c:<28} mediana {st.median(v):>6.0f} ms   p95 {p95:>6} ms   min {v[0]:>6}   max {v[-1]:>6}")
'
}

carga() {
  NIV=${*:-1 2 4 8 16}
  echo "== Carga de RADIUS: autenticaciones EAP-TLS completas con eapol_test (local en ldap-radius)"
  echo "   Cada autenticación incluye el túnel TLS, la búsqueda en LDAP (usuario y grupos) y el aviso REST a identity."
  radius "sudo bash -s" <<EOF
set -e
D=/etc/freeradius/3.0/certs-r1; T=/tmp/eapcarga; rm -rf \$T; mkdir -p \$T
for u in alu01 doc01 adm01 admin01; do
cat > \$T/\$u.conf <<C
network={
    key_mgmt=WPA-EAP
    eap=TLS
    identity="\$u"
    ca_cert="\$D/ca.pem"
    client_cert="\$D/clientes/\$u.pem"
    private_key="\$D/clientes/\$u.key"
}
C
done
SECRET=\$(cat /root/g05-r1/radius_secret)
printf "%-10s %-10s %-8s %-8s %-10s %-12s %-10s\n" paralelos total ok fallos seg auth/s cpu_radius_%
for p in $NIV; do
  n=\$((p * 10 > 40 ? p * 10 : 40))
  c0=\$(awk '{print \$14+\$15}' /proc/\$(pidof freeradius)/stat)
  t0=\$(date +%s.%N)
  export T SECRET
  seq 1 \$n | xargs -P \$p -I{} sh -c 'set -- alu01 doc01 adm01 admin01; shift \$(( {} % 4 )); eapol_test -c "\$T/\$1.conf" -a 127.0.0.1 -s "\$SECRET" -t 10 >/dev/null 2>&1 && echo ok || echo fallo' > \$T/res
  t1=\$(date +%s.%N)
  c1=\$(awk '{print \$14+\$15}' /proc/\$(pidof freeradius)/stat)
  ok=\$(grep -c ok \$T/res || true); fa=\$(grep -c fallo \$T/res || true)
  awk -v p=\$p -v n=\$n -v ok=\$ok -v fa=\$fa -v t0=\$t0 -v t1=\$t1 -v c=\$((c1 - c0)) -v hz=\$(getconf CLK_TCK) \
    'BEGIN{d=t1-t0; printf "%-10s %-10s %-8s %-8s %-10.1f %-12.1f %-10.0f\n", p, n, ok, fa, d, ok/d, 100*c/hz/d}'
  sleep 2
done
echo "CPUs ldap-radius: \$(nproc)"
rm -rf \$T
EOF
}

accion=${1:-invalidos}; shift || true
case "$accion" in
  invalidos) invalidos "$@" ;;
  latencia)  latencia "$@" ;;
  carga)     carga "$@" ;;
  *) echo "uso: $0 invalidos|latencia|carga" >&2; exit 1 ;;
esac
