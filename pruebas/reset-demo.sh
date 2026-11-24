#!/bin/bash
# Restauración limpia para la sustentación (G05): deja el slice como antes de un escenario.
#  - Alumno: cierra las 6 sesiones 802.1X, borra IPs y detiene hping3/nmap/curl de ataques
#  - identity: levanta bloqueos (R3), límites (R4) y cuarentenas; borra las sesiones
#  - ldap-radius: desbloquea las cuentas bloqueadas por intentos fallidos (R1-03)
#  - comprueba que los servicios y el clúster estén arriba
# No borra registros (son evidencia): imprime una marca `desde=` para filtrar lo nuevo con
#   bash pruebas/incidentes.sh <minutos>   o   GET /identity/incidents?desde=<marca>
# Se ejecuta desde el Mac con los canales ~/.ssh/ctl-<puerto> abiertos. bash 3.2.
GW=10.20.12.7
c() { perl -e 'alarm 60; exec @ARGV' ssh -S ~/.ssh/ctl-$1 x@$GW "${@:2}"; }
MACS="01 02 03 04 05 06"

echo "== Alumno: sesiones y ataques"
c 5813 'sudo pkill -x hping3; sudo pkill -x nmap; for ns in u-inv u-alu u-doc u-adm u-net u-cic; do sudo g05-r1 logout $ns >/dev/null 2>&1; sudo ip netns exec $ns ip -4 addr flush dev $ns; done; echo "  6 usuarios sin sesión ni IP"'

echo "== identity: bloqueos, límites, cuarentenas y sesiones"
c 5806 "for m in $MACS; do M=02:05:00:00:00:\$m; for r in block limit quarantine sessions; do curl -s -o /dev/null -X DELETE http://127.0.0.1:5001/identity/\$r/\$M; done; done
  echo \"  bloqueos activos: \$(curl -s http://127.0.0.1:5001/identity/blocks)  límites: \$(curl -s http://127.0.0.1:5001/identity/trafico | python3 -c 'import json,sys; print(len(json.load(sys.stdin)[\"limitados\"]))')  sesiones: \$(curl -s http://127.0.0.1:5001/identity/sessions | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')\""

echo "== ldap-radius: cuentas bloqueadas por intentos fallidos"
c 5809 'b=$(sudo g05-bloqueo estado | awk "/bloqueada=sí/{print \$1}"); if [ -n "$b" ]; then sudo systemctl stop g05-bloqueo; for u in $b; do sudo g05-bloqueo desbloquear $u; done; sudo systemctl start g05-bloqueo; else echo "  ninguna cuenta bloqueada"; fi'

echo "== Servicios"
c 5806 'echo "  onos-1: identity $(systemctl is-active g05-identity), aaa-agent $(systemctl is-active g05-aaa-agent), contenedores: $(sudo docker ps --format {{.Names}} | tr "\n" " ")"'
c 5809 'echo "  ldap-radius: freeradius $(systemctl is-active freeradius), slapd $(systemctl is-active slapd), g05-bloqueo $(systemctl is-active g05-bloqueo)"'
c 5812 'echo "  ids: suricata $(systemctl is-active suricata), ids-agent $(systemctl is-active g05-ids-agent)"'
c 5811 'echo "  recursos: g05-svc $(systemctl is-active g05-svc)"'
c 5806 'curl -sn http://127.0.0.1:8181/onos/v1/cluster | python3 -c "import json,sys; print(\"  clúster ONOS:\", \", \".join(n[\"ip\"] + \" \" + n[\"status\"] for n in json.load(sys.stdin)[\"nodes\"]))"
  curl -sn http://127.0.0.1:8181/onos/v1/devices | python3 -c "import json,sys; d=json.load(sys.stdin)[\"devices\"]; print(\"  switches disponibles:\", sum(x[\"available\"] for x in d), \"de\", len(d))"'
c 5806 'l=$(df -m --output=avail / | tail -1); echo "  disco libre en onos-1: ${l} MB"; [ "$l" -lt 200 ] && echo "  AVISO: poco disco: identity no podrá guardar sesiones. Libera con: sudo apt-get clean; sudo journalctl --vacuum-size=30M"'
echo; echo "Listo. Marca para filtrar el registro de esta demo: desde=$(c 5806 'date +%s')"
