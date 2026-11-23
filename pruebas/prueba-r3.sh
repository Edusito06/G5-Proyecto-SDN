#!/bin/bash
# Pruebas de R3 (G05): ataques encubiertos desde un usuario autenticado y su mitigación.
# Se ejecuta desde el Mac con los canales ~/.ssh/ctl-<puerto> (5806 ONOS-1, 5813 Alumno).
# Compatible con bash 3.2.
#
#  atacante: alu01 (802.1X) en el namespace u-alu
#  testigo:  invitado en u-inv (sin 802.1X, comparte el puerto sin chocar con AAA)
#
# Por cada ataque: se levanta cualquier bloqueo previo, se comprueba que el atacante
# llega al Portal (permitido para su rol), se lanza el ataque y se mide, con el reloj
# de la VM Alumno, cuánto tarda en perder el acceso (detección + mitigación). Después
# se comprueba que el testigo sigue llegando a la Mesa de ayuda.
GW=10.20.12.7
ATK_NS=u-alu; ATK_MAC=02:05:00:00:00:02; ATK_USER=alu01
OBS_NS=u-inv; OBS_MAC=02:05:00:00:00:01
PORTAL=10.100.1.10; AYUDA=10.100.1.150
alumno() { ssh -S ~/.ssh/ctl-5813 x@$GW "$@"; }
onos1() { ssh -S ~/.ssh/ctl-5806 x@$GW "$@"; }
idn() { onos1 "curl -s -X $1 http://127.0.0.1:5001/identity/$2"; }

preparar() {
  echo "== Preparación: atacante 802.1X y testigo invitado"
  alumno 'for ns in u-inv u-alu u-doc u-adm u-net u-cic; do sudo g05-r1 logout $ns >/dev/null; done'
  idn DELETE "sessions/$OBS_MAC" >/dev/null
  alumno "sudo g05-r1 login $ATK_NS $ATK_USER; sleep 2; sudo g05-r1 dhcp $ATK_NS"
  idn POST "guest/$OBS_MAC" >/dev/null; sleep 3
  alumno "sudo g05-r1 dhcp $OBS_NS"
}

levantar() {  # levanta el bloqueo y espera a que el atacante vuelva a llegar al Portal
  # (9 s: cubre la gracia de 8 s del sensor de spoofing de identity tras levantar)
  for i in 1 2 3; do
    idn DELETE "block/$ATK_MAC" >/dev/null; sleep 9
    [ "$(acceso $ATK_NS $PORTAL 443)" = sí ] && return
  done
}

acceso() {  # $1 ns, $2 ip, $3 puerto -> sí/no
  alumno "sudo ip netns exec $1 timeout 3 nc -z -w2 $2 $3 && echo sí || echo no"
}

atacar() {  # $1 nombre, $2 comando del ataque (se ejecuta en el namespace del atacante)
  echo; echo "=== $1"
  levantar
  echo "  antes: atacante->Portal $(acceso $ATK_NS $PORTAL 443)"
  r=$(alumno "sudo ip netns exec $ATK_NS bash -s" <<EOF
t0=\$(date +%s.%N)
( $2 ) >/dev/null 2>&1 &
res=SIN_MITIGACION
for i in \$(seq 1 120); do
  ts=\$(date +%s.%N)
  if ! timeout 1 nc -z -w1 $PORTAL 443 2>/dev/null; then res=\$(awk "BEGIN{printf \"%.1f\", \$ts-\$t0}"); break; fi
  sleep 0.25
done
wait
echo "\$res"
EOF
)
  echo "  atacante pierde el acceso a los: ${r} s"
  echo "  testigo (invitado) -> Mesa de ayuda: $(acceso $OBS_NS $AYUDA 80)"
  onos1 "sudo journalctl -u g05-identity --since '-90s' --no-pager | grep -oE '\{.*\}' | grep -E 'ALERTA_IDS|\"BLOQUEO' | tail -2 | cut -c1-230" | sed 's/^/  /'
  RESULTADOS="$RESULTADOS
$1|$r"
}

trafico_normal() {
  echo; echo "=== Falsos positivos: 60 s de tráfico legítimo del atacante (antes de atacar)"
  levantar
  antes=$(onos1 "sudo journalctl -u g05-identity --no-pager | grep -c ALERTA_IDS")
  alumno "sudo ip netns exec $ATK_NS bash -s" <<'EOF'
for t in 10.100.1.10:443 10.100.1.150:80 10.100.1.150:443 10.100.0.50:443 10.100.0.130:443; do
  for p in 22 80 443; do (timeout 3 nc -z -w2 ${t%:*} $p &) ; done
done; wait
for i in $(seq 1 30); do
  timeout 3 nc -w2 10.100.1.10 443 </dev/null >/dev/null
  curl -s -m2 -o /dev/null http://10.100.1.150/ayuda?tema=$i
  printf x | timeout 2 nc -u -w1 10.100.1.130 53 >/dev/null
  sleep 2
done
EOF
  despues=$(onos1 "sudo journalctl -u g05-identity --no-pager | grep -c ALERTA_IDS")
  echo "  alertas durante el tráfico legítimo: $((despues - antes))"
  echo "  atacante->Portal al terminar: $(acceso $ATK_NS $PORTAL 443)"
}

preparar
trafico_normal
atacar "Escaneo de puertos (nmap SYN a 101 puertos)" "nmap -sS -Pn -n -T4 --max-retries 0 -p 1000-1100 $AYUDA"
atacar "Escaneo de red (barrido ICMP a 40 hosts)" "for i in \$(seq 1 40); do ping -c1 -W1 10.100.0.\$((i+60)) & sleep 0.05; done; wait"
atacar "Escaneo de red (nmap -sn -PS80 a 64 hosts de otra subred)" "nmap -sn -PS80 -n -T4 10.30.0.0/26"
atacar "IP spoofing externo (hping3 -a 198.51.100.7)" "hping3 -S -a 198.51.100.7 -p 80 -c 40 -i u20000 $AYUDA"
atacar "IP spoofing interno (hping3 -a 10.20.0.77, misma subred)" "hping3 -S -a 10.20.0.77 -p 80 -c 40 -i u20000 $AYUDA"
atacar "Request malicioso (inyección SQL)" "curl -s -m2 'http://$AYUDA/buscar?q=1%20UNION%20SELECT%20usuario,clave%20FROM%20cuentas'"
atacar "Request malicioso (path traversal)" "curl -s -m2 --path-as-is 'http://$AYUDA/../../etc/passwd'"
atacar "Bot: ráfaga de 60 requests HTTP" "for i in \$(seq 1 60); do curl -s -m2 -o /dev/null http://$AYUDA/ & done; wait"
levantar
echo; echo "=== Resumen (segundos hasta que el atacante pierde el acceso)"
echo "$RESULTADOS" | sed '/^$/d' | awk -F'|' '{printf "  %-58s %s\n", $1, $2}'
