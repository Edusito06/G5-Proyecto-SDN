#!/bin/bash
# Espejo de R3 en R-SW1 (G05): copia el tráfico del puerto de usuarios (ens7) en ambos
# sentidos hacia el IDS dentro de un túnel GRE (estilo ERSPAN) por la red de gestión.
#
# Por qué GRE y no el enlace directo R-SW1/ens6 -> IDS: el VNRT solo entrega a la VM IDS
# las tramas dirigidas a su propia MAC (más broadcast), así que el tráfico espejado
# unicast se perdía. Encapsulado en GRE hacia 192.168.0.22 sí llega. Es un espejo de
# OVSDB (no OpenFlow): no altera el pipeline de R2 ni las reglas de control.
# Uso (en R-SW1, con sudo):  g05-espejo [crear|borrar|estado]
set -euo pipefail
BR=br0; USUARIOS=ens7; NOMBRE=g05-ids; TUNEL=ids-gre
LOCAL=192.168.0.13; IDS=192.168.0.22
accion=${1:-crear}
case "$accion" in
  crear)
    if ! ovs-vsctl --if-exists get Interface "$TUNEL" type >/dev/null 2>&1 || \
       [ -z "$(ovs-vsctl --if-exists get Interface "$TUNEL" type)" ]; then
      ovs-vsctl add-port "$BR" "$TUNEL" -- set Interface "$TUNEL" type=gre \
        options:remote_ip="$IDS" options:local_ip="$LOCAL" options:df_default=false \
        options:key=4735 external_ids:g05-espejo=true >/dev/null
    fi
    # El puerto del túnel no debe recibir tráfico por OpenFlow (solo copias del espejo).
    ovs-ofctl -O OpenFlow13 mod-port "$BR" "$TUNEL" no-flood 2>/dev/null || true
    m=$(ovs-vsctl --bare --columns=_uuid find Mirror name="$NOMBRE")
    [ -n "$m" ] && ovs-vsctl remove Bridge "$BR" mirrors "$m"
    ovs-vsctl -- --id=@u get Port "$USUARIOS" -- --id=@t get Port "$TUNEL" \
              -- --id=@m create Mirror name="$NOMBRE" select-src-port=@u select-dst-port=@u output-port=@t \
              -- add Bridge "$BR" mirrors @m >/dev/null
    echo "espejo $NOMBRE: $USUARIOS -> GRE $LOCAL -> $IDS" ;;
  borrar)
    m=$(ovs-vsctl --bare --columns=_uuid find Mirror name="$NOMBRE")
    [ -n "$m" ] && ovs-vsctl remove Bridge "$BR" mirrors "$m"
    ovs-vsctl --if-exists del-port "$BR" "$TUNEL"
    echo "espejo $NOMBRE retirado" ;;
  estado)
    ovs-vsctl --columns=name,select_src_port,select_dst_port,output_port,statistics list Mirror ;;
esac
