#!/bin/bash
# Simula la caída del dominio de falla DF1 en el plano de control: detiene ONOS-1 y
# Atomix-1 (contenedores en la VM onos-1) y mide cuánto tarda ONOS-2 en quedar como
# master de los 6 switches. Al final restaura ambos contenedores.
# Compatible con bash 3.2 (macOS). Requiere los canales ~/.ssh/ctl-<puerto>.
GW=10.20.12.7
PUERTOS="5800 5801 5802 5803 5804 5805"

roles() {  # cuántos switches tienen a ONOS-2 como master
  local p n=0
  for p in $PUERTOS; do
    ssh -S ~/.ssh/ctl-$p x@$GW 'sudo ovs-vsctl --columns=target,role list Controller' \
      | tr -d ' "' | paste - - - | grep -q 'target:tcp:10.100.0.9:6653.*role:master' && n=$((n+1))
  done
  echo $n
}
detalle() {
  local p
  for p in $PUERTOS; do
    ssh -S ~/.ssh/ctl-$p x@$GW 'echo -n "$(hostname): "; sudo ovs-vsctl --columns=target,is_connected,role list Controller | tr -d " \"" | grep -oE "target:tcp:[0-9.]+|is_connected:[a-z]+|role:[a-z]*" | sed "s/target:tcp://" | paste -d" " - - - | tr "\n" "| "; echo'
  done
}

echo "=== Antes"; detalle
echo; echo "=== Se detienen ONOS-1 y Atomix-1 (caída de DF1)"
t0=$(date +%s)
ssh -S ~/.ssh/ctl-5806 x@$GW 'sudo docker stop -t 2 onos atomix >/dev/null'
while :; do
  n=$(roles); t=$(( $(date +%s) - t0 ))
  echo "  t=${t}s  switches con ONOS-2 como master: $n/6"
  [ "$n" = 6 ] && break
  [ $t -ge 120 ] && { echo "  (no convergió en 120 s)"; break; }
  sleep 2
done
echo; echo "=== Con DF1 caído"; detalle
echo; echo "Atomix-2 y Atomix-3 (2 de 3 votos):"
for p in 5807 5808; do
  ssh -S ~/.ssh/ctl-$p x@$GW 'echo "  $(hostname): $(sudo docker logs --since 3m atomix 2>&1 | grep -oE "Found leader atomix-[0-9]|Transitioning to LEADER|Member deactivated: Member\{id=atomix-1" | sort | uniq -c | tr -s " " | tr "\n" ";")"'
done
echo; echo "=== Se restauran ONOS-1 y Atomix-1"
ssh -S ~/.ssh/ctl-5806 x@$GW 'sudo docker start atomix onos >/dev/null && echo "  contenedores iniciados"'
