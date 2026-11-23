#!/bin/bash
# Registro consolidado de incidentes de R3 (G05).
# Lee /identity/incidents (JSONL persistente de identity en ONOS-1) y arma una fila por
# incidente: alerta del IDS o sensor del switch -> bloqueo -> regla aplicada -> fin.
# Uso: bash pruebas/incidentes.sh [minutos_atrás (def. 60)] [archivo.csv opcional]
GW=10.20.12.7
MIN=${1:-60}; CSV=${2:-}
desde=$(( $(date +%s) - MIN * 60 - 60 ))   # holgura: el reloj de ONOS-1 va unos s adelante
ssh -S ~/.ssh/ctl-5806 x@$GW "curl -s 'http://127.0.0.1:5001/identity/incidents?desde=$desde'" |
python3 -c '
import csv, json, sys
regs = json.load(sys.stdin)
inc, abiertos = [], {}
alerta = {}                                   # mac -> última ALERTA_IDS (para unir con el bloqueo)
for r in regs:
    ev, mac = r["ev"], r.get("mac")
    if ev == "ALERTA_IDS":
        alerta[mac] = r
    elif ev == "BLOQUEO":
        a = alerta.pop(mac, None) if r.get("fuente") == "ids" else None
        fila = {"inicio": r["fecha"], "usuario": r.get("usuario") or "-", "mac": mac,
                "ip_origen": (a or {}).get("src_ip", "-"), "fuente": r.get("fuente"),
                "sid": (a or {}).get("sid", "-"), "motivo": r.get("motivo", "")[:60],
                "agente_ms": r.get("retardo_agente_ms", "-"), "reglas_ms": "-",
                "fin": "-", "cierre": "ABIERTO", "duracion_s": "-", "_ts": r["ts"]}
        inc.append(fila); abiertos[mac] = fila
    elif ev == "MITIGACION_APLICADA" and mac in abiertos and abiertos[mac]["reglas_ms"] == "-":
        abiertos[mac]["reglas_ms"] = r.get("ms")
    elif ev in ("BLOQUEO_LEVANTADO", "BLOQUEO_VENCIDO") and mac in abiertos:
        f = abiertos.pop(mac)
        f.update(fin=r["fecha"], cierre="LEVANTADO" if ev == "BLOQUEO_LEVANTADO" else "VENCIDO",
                 duracion_s=round(r["ts"] - f["_ts"], 1))
    elif ev == "CUARENTENA":
        inc.append({"inicio": r["fecha"], "usuario": "-", "mac": mac, "ip_origen": "-",
                    "fuente": "reincidencia", "sid": "-", "motivo": ("CUARENTENA: " + r.get("motivo", ""))[:60],
                    "agente_ms": "-", "reglas_ms": "-", "fin": "-", "cierre": "-", "duracion_s": "-", "_ts": r["ts"]})
cols = ["inicio", "usuario", "mac", "ip_origen", "fuente", "sid", "motivo", "agente_ms", "reglas_ms", "cierre", "duracion_s"]
n_ids = sum(1 for f in inc if f["fuente"] == "ids")
n_sw = sum(1 for f in inc if f["fuente"] == "switch")
print(f"{len(inc)} incidentes ({n_ids} del IDS, {n_sw} del sensor del switch)")
fmt = "{:<19} {:<8} {:<17} {:<14} {:<12} {:<8} {:<60} {:>9} {:>9} {:<9} {:>10}"
print(fmt.format(*cols))
for f in inc:
    print(fmt.format(f["inicio"][:19], *(str(f[c]) for c in cols[1:])))
if len(sys.argv) > 1 and sys.argv[1]:
    with open(sys.argv[1], "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols + ["fin"], extrasaction="ignore"); w.writeheader(); w.writerows(inc)
    print("CSV:", sys.argv[1])
' "$CSV"
