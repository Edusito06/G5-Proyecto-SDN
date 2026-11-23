#!/bin/bash
# Trazabilidad de R2 (G05): ¿cada intento que la política deniega queda registrado con
# el usuario que lo hizo? Corre la matriz completa (`r2ctl verify --roles all`, 802.1X
# real, 6 roles x 36 destinos) y la cruza con los INTENTO_DENEGADO de identity.
#   cobertura   = pares (rol, destino) denegados en la matriz que aparecen en el registro
#   atribución  = registros con el usuario 802.1X correcto para ese rol
#   falsos      = registros sobre un destino/puerto que la política sí permite
# Se ejecuta desde el Mac, con el venv de Proyecto-R2 y los canales ~/.ssh/ctl-<puerto>.
cd "$(dirname "$0")/../politica"
GW=10.20.12.7
PY=${PY:-../../Proyecto-R2/.venv/bin/python}
MATRIZ=$(mktemp -t r2-matriz)
desde=$(ssh -S ~/.ssh/ctl-5806 x@$GW 'date +%s')
R2_VERIFY_JSON=$MATRIZ $PY r2ctl.py verify --roles all | grep -E "rol|Pruebas|Precisión|DISCREP"
sleep 8                                         # que el agente del IDS termine de avisar
ssh -S ~/.ssh/ctl-5806 x@$GW "curl -s 'http://127.0.0.1:5001/identity/incidents?desde=$desde'" > "$MATRIZ.reg"
python3 - "$MATRIZ" "$MATRIZ.reg" <<'PY'
import json, sys
from collections import defaultdict
matriz = json.load(open(sys.argv[1]))
regs = [r for r in json.load(open(sys.argv[2])) if r.get('ev') == 'INTENTO_DENEGADO']
# usuario esperado por rol en el ciclo de verify (cuarentena: alu01 puesto en cuarentena)
USUARIO = {5: 'admin01', 4: 'adm01', 3: 'doc01', 2: 'alu01', 1: 'invitado', 9: 'alu01'}
neg = defaultdict(int)                          # (rol, ip) -> pruebas denegadas
permitido = set()                               # (rol, ip, proto, puerto) permitidos
for p in matriz:
    if p['esperado']:
        permitido.add((p['rol'], p['ip'], p['proto'], p['puerto']))
    elif p['obtenido'] is False:
        neg[(p['rol'], p['ip'])] += 1
log = defaultdict(list)
falsos = 0
for r in regs:
    ip, _, resto = r['dst'].partition(':')
    puerto, _, proto = resto.partition('/')
    k = (r.get('rol'), ip)
    log[k].append(r)
    if puerto.isdigit() and (r.get('rol'), ip, proto.lower(), int(puerto)) in permitido:
        falsos += 1
cub = [k for k in neg if k in log]
bien = sum(1 for k in cub for r in log[k] if r.get('usuario') == USUARIO.get(k[0]))
total_reg = sum(len(log[k]) for k in cub)
print(f"\nIntentos denegados en la matriz: {sum(neg.values())} pruebas, {len(neg)} pares (rol, destino)")
print(f"Cobertura del registro: {len(cub)}/{len(neg)} pares ({100*len(cub)/max(1,len(neg)):.1f} %)")
print(f"Atribución al usuario correcto: {bien}/{total_reg} registros")
sin = [r for r in regs if not r.get('usuario')]
print(f"Registros sin usuario (origen sin sesión): {len(sin)}")
print(f"Registros sobre accesos permitidos (falsos): {falsos} de {len(regs)}")
falt = sorted(k for k in neg if k not in log)
if falt:
    print("Sin registro:", ", ".join(f"rol {r} -> {ip}" for r, ip in falt))
print("\nEjemplo de registro:")
print(" ", json.dumps({k: regs[0][k] for k in ('fecha', 'usuario', 'rol', 'mac', 'dst', 'recurso')}, ensure_ascii=False) if regs else "  (sin registros)")
PY
rm -f "$MATRIZ" "$MATRIZ.reg"
