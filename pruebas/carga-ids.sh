#!/bin/bash
# Prueba de carga del IDS (R3, G05): sesiones maliciosas por segundo sin degradación.
# Desde u-alu se lanzan sesiones HTTP con inyección SQL (sid 1000010, sin umbral: una
# alerta por sesión) a tasas crecientes. Por tasa se mide:
#   - sesiones completadas (el servidor respondió)   - alertas 1000010 en eve.json
#   - tasa de detección = alertas / sesiones           - kernel_drops de AF_PACKET
#   - CPU de Suricata (pidstat no está: se usa /proc)
# Durante la prueba se detiene g05-ids-agent para que el bloqueo no corte las sesiones
# (se mide la capacidad del IDS, no la mitigación); al final se vuelve a activar.
# Uso: bash pruebas/carga-ids.sh [tasas...]   (def. 10 25 50 100 200 400), 20 s por tasa
GW=10.20.12.7; DUR=20
TASAS=${*:-10 25 50 100 200 400}
alumno() { ssh -S ~/.ssh/ctl-5813 x@$GW "$@"; }
ids() { ssh -S ~/.ssh/ctl-5812 x@$GW "$@"; }
onos1() { ssh -S ~/.ssh/ctl-5806 x@$GW "$@"; }

contar_ids() {  # alertas sid 1000010 totales, kernel_packets, kernel_drops, ticks CPU de suricata
  ids 'a=$(sudo grep -c "\"signature_id\":1000010" /var/log/suricata/eve.json)
       st=$(sudo grep "\"event_type\":\"stats\"" /var/log/suricata/eve.json | tail -1)
       kp=$(echo "$st" | grep -oE "\"kernel_packets\":[0-9]+" | head -1 | cut -d: -f2)
       kd=$(echo "$st" | grep -oE "\"kernel_drops\":[0-9]+" | head -1 | cut -d: -f2)
       pid=$(pidof suricata); cpu=$(awk "{print \$14+\$15}" /proc/$pid/stat)
       echo "$a ${kp:-0} ${kd:-0} $cpu $(getconf CLK_TCK) $(nproc)"'
}

echo "== Preparación"
ids 'sudo systemctl stop g05-ids-agent; sudo sed -i "s/interval: 30/interval: 5/" /etc/suricata/g05.yaml; sudo systemctl restart suricata'
sleep 12
onos1 'curl -s -X DELETE http://127.0.0.1:5001/identity/block/02:05:00:00:00:02 >/dev/null'
sleep 9
echo "  agente detenido, stats cada 5 s, atacante desbloqueado"

GEN=$(cat <<'PY'
import socket, sys, threading, time
rate, dur, host = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
ok = [0]; err = [0]; lk = threading.Lock()
req = (b"GET /buscar?q=1%20UNION%20SELECT%20usuario,clave%20FROM%20cuentas HTTP/1.1\r\n"
       b"Host: " + host.encode() + b"\r\nUser-Agent: carga-g05\r\nConnection: close\r\n\r\n")
def una():
    try:
        s = socket.create_connection((host, 80), timeout=3); s.sendall(req)
        r = s.recv(256); s.close()
        with lk: (ok if r.startswith(b"HTTP/1.1 200") else err)[0] += 1
    except OSError:
        with lk: err[0] += 1
t0 = time.time(); n = 0
while time.time() - t0 < dur:
    objetivo = int((time.time() - t0) * rate)
    while n < objetivo:
        threading.Thread(target=una, daemon=True).start(); n += 1
    time.sleep(0.005)
time.sleep(4)
print(n, ok[0], err[0])
PY
)
printf "\n%-8s %-9s %-9s %-8s %-10s %-11s %-10s %-8s\n" tasa/s lanzadas ok alertas deteccion kernel_pkts drops cpu_%
for r in $TASAS; do
  read a0 kp0 kd0 c0 hz nc <<<"$(contar_ids)"
  read n ok err <<<"$(alumno "sudo ip netns exec u-alu python3 -c '$GEN' $r $DUR 10.100.1.150")"
  sleep 8   # que Suricata escriba las alertas y un ciclo de stats
  read a1 kp1 kd1 c1 _ _ <<<"$(contar_ids)"
  al=$((a1 - a0)); det=$(awk "BEGIN{printf \"%.1f%%\", ($ok>0)?100*$al/$ok:0}")
  cpu=$(awk "BEGIN{printf \"%.1f\", 100*($c1-$c0)/$hz/($DUR+8+3)}")
  printf "%-8s %-9s %-9s %-8s %-10s %-11s %-10s %-8s\n" "$r" "$n" "$ok" "$al" "$det" "$((kp1 - kp0))" "$((kd1 - kd0))" "$cpu"
  sleep 3
done

echo; echo "== Restauración"
ids 'sudo sed -i "s/interval: 5/interval: 30/" /etc/suricata/g05.yaml; sudo systemctl restart suricata; sleep 6; sudo systemctl start g05-ids-agent; echo "  suricata $(systemctl is-active suricata), agente $(systemctl is-active g05-ids-agent), CPUs IDS: $(nproc)"'
onos1 'curl -s -X DELETE http://127.0.0.1:5001/identity/block/02:05:00:00:00:02 >/dev/null'
