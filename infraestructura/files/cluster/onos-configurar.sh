#!/bin/bash
# Configura el clúster ONOS recién creado ANTES de aceptar switches, en este orden:
#   1. allowExtraneousRules / allowExtraneousGroups (si no, ONOS borraría las reglas
#      de control locales y los grupos Fast Failover al reconectarse los switches)
#   2. LLDP y la app org.g05.inband con su configuración del árbol
#   3. recién entonces el proveedor OpenFlow
# Se ejecuta en un nodo ONOS con ~/.netrc. El OAR se pasa como primer argumento.
set -euo pipefail
oar=$1
API=http://127.0.0.1:8181/onos/v1
c() { curl -s -n -f "$@"; }
post_cfg() { c -X POST -H 'Content-Type: application/json' -d "$2" "$API/configuration/$1" >/dev/null; }

echo "Esperando la API REST..."
until c "$API/cluster" >/dev/null 2>&1; do sleep 3; done
until c "$API/configuration/org.onosproject.net.flow.impl.FlowRuleManager" 2>/dev/null | grep -q allowExtraneousRules; do sleep 3; done
until c "$API/configuration/org.onosproject.store.group.impl.DistributedGroupStore" 2>/dev/null | grep -q allowExtraneousGroups; do sleep 3; done

post_cfg org.onosproject.net.flow.impl.FlowRuleManager '{"allowExtraneousRules":"true"}'
post_cfg org.onosproject.store.group.impl.DistributedGroupStore '{"allowExtraneousGroups":"true"}'
c "$API/configuration/org.onosproject.net.flow.impl.FlowRuleManager" | grep -q '"allowExtraneousRules":"true"'
c "$API/configuration/org.onosproject.store.group.impl.DistributedGroupStore" | grep -q '"allowExtraneousGroups":"true"'
echo "Reglas y grupos externos permitidos"

c -X POST "$API/applications/org.onosproject.lldpprovider/active" >/dev/null
if ! c "$API/applications/org.g05.inband" >/dev/null 2>&1; then
  c -X POST -H 'Content-Type: application/octet-stream' --data-binary @"$oar" "$API/applications?activate=false" >/dev/null
fi
c -X POST "$API/applications/org.g05.inband/active" >/dev/null
until c "$API/configuration/org.g05.inband.Bootstrap" 2>/dev/null | grep -q rootPort; do sleep 2; done
post_cfg org.g05.inband.Bootstrap '{"rootPort":"3","ports":"of:0000000000000003/3,of:0000000000000003/4,of:0000000000000003/5,of:0000000000000003/6,of:0000000000000004/3,of:0000000000000005/1,of:0000000000000005/2,of:0000000000000005/3,of:0000000000000006/1,of:0000000000000007/1,of:0000000000000008/1","attachments":"10.100.0.3=of:0000000000000005/1,10.100.0.4=of:0000000000000005/2,10.100.0.6=of:0000000000000003/4,10.100.0.7=of:0000000000000003/5,10.100.0.8=of:0000000000000003/6"}'
echo "App org.g05.inband activa y configurada"

c -X POST "$API/applications/org.onosproject.openflow/active" >/dev/null
echo "Proveedor OpenFlow activo: los switches pueden reconectarse"
