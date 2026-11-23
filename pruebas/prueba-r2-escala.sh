#!/bin/bash
# Escalabilidad de R2 (G05): reglas, tiempo de programación y recursos de R-SW1 y ONOS
# con 0/50/100/200 sesiones activas, y tasa de nuevas sesiones.
# Desde el Mac con los canales ~/.ssh/ctl-<puerto> (5806 ONOS-1, 5803 R-SW1).
#
# El tiempo se mide en el switch: desde que se pide la reconciliación (lo mismo que hace
# identity con cada login) hasta que OVS tiene todas las reglas (ovs-ofctl). El estado
# ADDED de ONOS no sirve: ONOS lo confirma con su sondeo de estadísticas (~5 s).
# identity se detiene durante la prueba (las sesiones sintéticas no son suyas) y al final
# se reinicia: reconcilia R-SW1 con las sesiones reales.
cd "$(dirname "$0")"
scp -q -o ControlPath=~/.ssh/ctl-5806 ../politica/escala.py x@10.20.12.7:/tmp/escala.py
exec python3 - "$@" <<'PY'
import json, subprocess, sys, time
GW = '10.20.12.7'
def ssh(port, cmd):
    return subprocess.run(['ssh', '-S', f'{__import__("os").path.expanduser("~")}/.ssh/ctl-{port}', f'x@{GW}', cmd],
                          capture_output=True, text=True, timeout=300).stdout.strip()
onos1 = lambda c: ssh(5806, c)
rsw1 = lambda c: ssh(5803, c)
esc = lambda *a: json.loads(onos1('cd /opt/g05/politica && HOME=/home/ubuntu python3 escala.py ' + ' '.join(map(str, a))).splitlines()[-1])
ovs_n = lambda: int(rsw1('sudo ovs-ofctl -O OpenFlow13 dump-flows br0 | grep -c "table=[0-5],"'))

def cpu(port, patron):
    out = ssh(port, f'p=$(pgrep -f "{patron}" | head -1); a=$(sudo awk "{{print \\$14+\\$15}}" /proc/$p/stat); sleep 5; '
                    f'b=$(sudo awk "{{print \\$14+\\$15}}" /proc/$p/stat); r=$(sudo awk "/VmRSS/{{print \\$2}}" /proc/$p/status); '
                    f'echo $a $b $(getconf CLK_TCK) $r')
    a, b, hz, rss = map(int, out.split())
    return f'{100 * (b - a) / hz / 5:.1f}', rss // 1024

def fijar(n, objetivo_extra):
    """Pide la reconciliación y espera a que OVS tenga exactamente las reglas deseadas."""
    t0 = time.time()
    r = esc('fijar', n)
    t_rest = time.time()
    meta = r['reglas'] + objetivo_extra
    for _ in range(400):
        if ovs_n() == meta:
            break
        time.sleep(0.05)
    return r, int((t_rest - t0) * 1000), int((time.time() - t0) * 1000)

print('== Preparación: se detiene identity')
onos1('sudo install -m 644 -o ubuntu /tmp/escala.py /opt/g05/politica/escala.py; sudo systemctl stop g05-identity')
try:
    base = esc('base')
    otras = ovs_n() - base['reglas']           # reglas de otras apps (inband, redundancia)
    print(f'  base: {base["sesiones"]} sesiones reales, {base["reglas"]} reglas de r2ctl + {otras} de otras apps')
    print('\n== Sesiones activas (tiempo medido en OVS de R-SW1)')
    print(f'{"sesiones":<9} {"reglas_r2":<10} {"reglas_ovs":<11} {"+reglas":<8} {"rest_ms":<8} {"en_ovs_ms":<10} {"cpu_ovs":<8} {"rss_ovs":<8} {"cpu_onos":<9} {"rss_onos":<8}')
    for n in (0, 50, 100, 200):
        r, rest, tot = fijar(n, otras)
        time.sleep(3)
        co, ro = cpu(5803, 'ovs-vswitchd')
        cj, rj = cpu(5806, 'org.apache.karaf.main.Main')
        print(f'{r["sesiones"]:<9} {r["reglas"]:<10} {ovs_n():<11} {r["agregadas"]:<8} {r["rest_ms"]:<8} {tot:<10} {co:<8} {str(ro)+" MB":<8} {cj:<9} {str(rj)+" MB":<8}')
    print('\n== Tasa de nuevas sesiones: altas de a una (como cada login)')
    for n in (0, 200):
        fijar(n, otras)
        ms = sorted(fijar(n + j, otras)[2] for j in range(1, 11))
        print(f'  con {n + base["sesiones"]} activas: alta -> reglas en OVS mediana {ms[len(ms)//2]} ms, '
              f'máx {ms[-1]} ms (incluye ~2 llamadas SSH de medición) -> ~{1000 / ms[len(ms)//2]:.1f} altas/s en serie')
    print('\n== Ráfaga: 50 sesiones nuevas de golpe')
    for n in (0, 200):
        fijar(n, otras)
        r, rest, tot = fijar(n + 50, otras)
        print(f'  con {n + base["sesiones"]} activas: +{r["agregadas"]} reglas en OVS en {tot} ms -> {50000 / tot:.0f} sesiones/s')
finally:
    print('\n== Restauración')
    esc('base')
    onos1('sudo systemctl start g05-identity'); time.sleep(4)
    print('  identity', onos1('systemctl is-active g05-identity'))
PY
