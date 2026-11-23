#!/bin/bash
# Pruebas de falla del canal de control in-band (G05). Se ejecuta desde el Mac con los
# canales SSH ~/.ssh/ctl-<puerto> abiertos. Compatible con bash 3.2 (macOS).
# Cada prueba apaga interfaces con `ip link`, espera, mide y restaura.
GW=10.20.12.7
SWITCHES="core-1 core-2 dc-dist r-sw1 r-sw2 s-dist"

puerto() {
  case "$1" in
    core-1) echo 5800 ;; core-2) echo 5801 ;; dc-dist) echo 5802 ;;
    r-sw1) echo 5803 ;; r-sw2) echo 5804 ;; s-dist) echo 5805 ;;
    *) echo "switch desconocido: $1" >&2; exit 1 ;;
  esac
}
en() { local p; p=$(puerto "$1") || exit 1; ssh -S ~/.ssh/ctl-$p x@$GW "$2"; }

sesiones() {  # switch=segundos desde la última conexión (o CAIDO)
  local sw v
  for sw in $SWITCHES; do
    v=$(en "$sw" 'sudo ovs-vsctl --columns=is_connected,status list Controller' | tr -d ' "')
    if echo "$v" | grep -q 'is_connected:true'; then
      echo -n "$sw=$(echo "$v" | grep -o 'sec_since_connect=[0-9]*' | cut -d= -f2) "
    else
      echo -n "$sw=CAIDO "
    fi
  done
  echo
}
onos() {
  ssh -S ~/.ssh/ctl-5806 x@$GW 'curl -s -n http://127.0.0.1:8181/onos/v1/devices' | python3 -c '
import json,sys; n={"3":"core-1","4":"core-2","5":"dc-dist","6":"r-sw1","7":"r-sw2","8":"s-dist"}
d=json.load(sys.stdin)["devices"]
print("ONOS disponibles:", sorted(n[x["id"][-1]] for x in d if x["available"]), "| no disponibles:", sorted(n[x["id"][-1]] for x in d if not x["available"]))'
}
grupo() {  # paquetes por bucket (bucket0 = primario, bucket1 = respaldo)
  en "$1" "sudo ovs-ofctl -O OpenFlow13 dump-group-stats br0 group_id=$2" \
    | grep -o 'bucket[0-9]*:packet_count=[0-9]*' | tr '\n' ' '
  echo
}
prueba() {  # $1 descripción, $2 switch, $3 interfaces, $4 switch:grupo a observar
  local gsw="${4%%:*}" gid="${4##*:}"
  echo; echo "=== $1"
  echo -n "antes : "; sesiones
  echo -n "grupo $4 antes: "; grupo "$gsw" "$gid"
  en "$2" "for i in $3; do sudo ip link set dev \$i down; done"
  sleep 15
  echo -n "falla : "; sesiones; onos
  echo -n "grupo $4 en falla: "; grupo "$gsw" "$gid"
  en "$2" "for i in $3; do sudo ip link set dev \$i up; done"
  sleep 8
  echo -n "vuelta: "; sesiones
}

echo "Valor = segundos desde la última conexión OpenFlow. Si la falla no corta la"
echo "sesión, sigue creciendo entre 'antes', 'falla' y 'vuelta'; si la corta, se reinicia."
prueba "T1: cae el enlace Core-1 <-> R-SW1 (se apaga r-sw1/ens4)" r-sw1 ens4 r-sw1:50001
prueba "T2: cae el enlace Core-1 <-> DC-DIST (se apaga dc-dist/ens4)" dc-dist ens4 core-1:50001
prueba "T3: cae el enlace Core-2 <-> DC-DIST (se apaga dc-dist/ens5)" dc-dist ens5 dc-dist:50002
prueba "T4: cae Core-1 completo (todas sus interfaces de datos)" core-1 "ens5 ens6 ens7 ens8 ens9" r-sw2:50001
echo; onos
