# Contexto del proyecto en el VNRT · G05 (TEL354, 2026-2)

Resumen de todo lo implementado y probado en el slice del VNRT, cruzado con el repositorio (<https://github.com/Edusito06/G5-Proyecto-SDN>). Para cada pieza se indica **dónde corre**, **en qué ruta está instalada** y **qué archivo del repo la genera**. Estado al **24/11/2026**.

> Documentos relacionados en `documentacion/`:
> - `EXP_TEL354_LAB7_G5.pdf`: entregable de la experiencia.
> - `INFORME_PREVIO_TEL354_LAB7_G5.pdf`: informe previo.
> - `GUION_SUSTENTACION.md`: demo en vivo paso a paso.

---

## 1. Estado general

| Requerimiento | Estado | Evidencia principal | Código |
|---|---|---|---|
| Plano de control in-band + alta disponibilidad | ✅ Operativo | 6/6 switches; caída de DF1 → ONOS-2 toma todo en ~11 s; caída de enlaces o de Core-1 sin cortes | `infraestructura/` |
| **R1** · 802.1X, roles, multirol | ✅ | 21/21 accesos inválidos bloqueados; EAP-TLS en 82 ms; ~33 auth/s; bloqueo al 5.º fallo; multi01 → admin | `infraestructura/files/r1-identidad.sh`, `g05-bloqueo.py`, `politica/identity.py` |
| **R2** · recursos por rol | ✅ | 216 pruebas, 0 discrepancias, 142/142 bloqueados; 53/53 intentos registrados con usuario; 200 sesiones = 1 503 reglas | `politica/r2ctl.py`, `policy.yaml`, `identity.py` |
| **R3** · ataques encubiertos (específico del G05) | ✅ | 8/8 ataques mitigados en 0,3–4,5 s; 0 falsos positivos; IDS sin pérdidas a 400 sesiones/s | `infraestructura/files/ids/`, `identity.py` |
| **R4** · DDoS (adicional) | ✅ | Fuentes identificadas en ~14 s; víctima de 75–125 a 2–6 Mbit/s; testigo sin limitar | `politica/ddos.py`, `identity.py` |
| Pruebas | ✅ | **125 pruebas** (12 obligatorias del Lab 7); 89,5 % de cobertura de la lógica de decisión | `pruebas/unitarias/` |

---

## 2. Cómo entrar al slice

1. **VPN de la PUCP** (o estar en la red de la universidad). Sin ella, el gateway no responde.
2. **Gateway:** `10.20.12.7`. Cada VM se alcanza con un puerto del gateway (tabla de abajo), con el usuario `ubuntu` y su contraseña. Las contraseñas no están en el repo.
3. **Canales SSH persistentes.** Así no se escribe la contraseña en cada comando. Todos los scripts del repo los usan:

   ```bash
   for p in 22 5800 5801 5802 5803 5804 5805 5806 5807 5808 5809 5810 5811 5812 5813; do ssh -S ~/.ssh/ctl-$p -O exit ubuntu@10.20.12.7 2>/dev/null; rm -f ~/.ssh/ctl-$p; ssh -fN -M -S ~/.ssh/ctl-$p -p $p ubuntu@10.20.12.7; done
   ```

   Después, por ejemplo: `ssh -S ~/.ssh/ctl-5806 x@10.20.12.7 'hostname'` (el usuario `x` da igual con el canal abierto).

4. **Al cambiar de red** los canales quedan "vivos" en tu máquina pero muertos de verdad. Hay que cerrarlos y abrirlos de nuevo con el mismo bucle.
5. **REST de ONOS:** solo en ONOS-1, en `127.0.0.1:8181`, con `~/.netrc` (`curl -sn`). ONOS-2 no tiene `.netrc`.

| Puerto | VM | Gestión (ens3) | Dominio | Función |
|---|---|---|---|---|
| 22 | gw | 10.20.12.7 | Borde | NAT y bastión SSH; copia del repo en `~/bootstrap-g05-fix-nowait` y `~/g05-politica` |
| 5800 | core-1 | 192.168.0.10 | DF1 | Switch núcleo y **router** entre las VLAN de rol y los servicios |
| 5801 | core-2 | 192.168.0.11 | DF3 | Switch núcleo de respaldo |
| 5802 | dc-dist | 192.168.0.12 | DF1 | Distribución del centro de datos (ONOS-1, LDAP, DNS, Recursos) |
| 5803 | r-sw1 | 192.168.0.13 | DF2 | **Switch de acceso** (usuarios, IDS); aplica R2/R3/R4 |
| 5804 | r-sw2 | 192.168.0.14 | DF2 | Acceso del edificio R (ONOS-2) |
| 5805 | s-dist | 192.168.0.15 | DF3 | Distribución del edificio S |
| 5806 | onos-1 | 192.168.0.16 | DF1 | ONOS + Atomix-1 (Docker); **identity** y aaa-agent |
| 5807 | onos-2 | 192.168.0.17 | DF2 | ONOS + Atomix-2 (Docker); aaa-agent |
| 5808 | atomix-3 | 192.168.0.18 | DF3 | Atomix-3 (árbitro Raft) |
| 5809 | ldap-radius | 192.168.0.19 | DF1 | OpenLDAP + FreeRADIUS + g05-bloqueo |
| 5810 | dns-dhcp | 192.168.0.20 | DF1 | Kea DHCPv4 (y DNS de prueba) |
| 5811 | recursos | 192.168.0.21 | DF1 | Servidores de prueba G02–G12 |
| 5812 | ids | 192.168.0.22 | DF2 | Suricata + ids-agent |
| 5813 | alumno | 192.168.0.23 | DF2 | Los 6 usuarios de prueba (namespaces) |

---

## 3. Redes y direccionamiento

| Red | Direccionamiento | Uso |
|---|---|---|
| Gestión (out-of-band) | 192.168.0.0/24 en `ens3` | SSH/Ansible, clúster ONOS (9876) y Atomix (5679), RADIUS, alertas del IDS, **espejo GRE** |
| Control (in-band) | 10.100.0.0/28: `br0` de core-1…s-dist = .3–.8 (DPID = último octeto); ONOS-1 = .2, ONOS-2 = .9 | OpenFlow 1.3 (TCP 6653) por los enlaces de datos |
| Usuarios | VLAN = rol × 100; subred 10.(rol×10).0.0/24; gateway .1 en Core-1 | Invitado 100 · alumno 200 · docente 300 · administrativo 400 · admin 500 · cuarentena 900 |
| Servicios | g02 10.100.0.16/28 (LDAP/RADIUS, VLAN 112) · g11 10.100.1.128/28 (DNS/DHCP, VLAN 111) · srv (recursos, VLAN 113) | Hacia DC-DIST |

R-SW1 (`of:0000000000000006`): puerto 1 = Core-1 (salida), 2 = Core-2, 3 = IDS, **4 = usuarios (VM Alumno)**.

---

## 4. Qué corre en cada VM y de dónde sale

Servicios verificados el 24/11 en core-1, core-2, r-sw1, r-sw2, onos-1, ldap-radius, recursos, ids y alumno. Lo de dc-dist, s-dist, onos-2, atomix-3 y dns-dhcp sale del repo y de las pruebas anteriores; ese día no tenían canal abierto.

| VM | Servicio / proceso | Ruta en la VM | Archivo del repo | Cómo se instala |
|---|---|---|---|---|
| 6 switches | OVS `br0` in-band, reglas LOCAL | timer `g05-paper-local` | `infraestructura/files/paper-bridge.py` | `paper.yml` (Ansible) |
| 6 switches | Redundancia: BFD + Fast Failover | `/usr/local/sbin/g05-redundancia`, timer `g05-redundancia` | `infraestructura/files/g05-redundancia.py` | `redundancia.yml` |
| core-1, dc-dist, r-sw1 | Segmentos VLAN de servicio | timer `g05-servicios` | `infraestructura/files/g05-servicios.py` | `servicios.yml` |
| core-1 | Router (tabla nftables `inet g05_router`, servicio `g05-router`) + `g05-dhcrelay` | servicios systemd | `infraestructura/files/g05-core1-router.nft` | `servicios.yml` |
| r-sw1 | Espejo del puerto de usuarios en GRE hacia el IDS | `g05-espejo.service` | `infraestructura/files/ids/g05-espejo.sh` | a mano (en el repo) |
| onos-1, onos-2, atomix-3 | ONOS 2.7 y Atomix 3.1.5 (Docker, red del host) | `/etc/g05-onos` (cluster.json) | `infraestructura/files/cluster/` | `cluster.yml` |
| onos-1 | **identity** (`g05-identity`, REST :5001) | `/opt/g05/politica/` (identity.py, r2ctl.py, ddos.py, policy.yaml, topology.yaml); sesiones en `/var/lib/r2/sessions.json`; registro de seguridad en `/var/log/g05/incidentes.jsonl` | `politica/` | `politica/instalar-identity.sh` |
| onos-1, onos-2 | aaa-agent (`g05-aaa-agent`) | `/opt/g05/aaa-agent.py` | `politica/aaa-agent.py` | `instalar-identity.sh` |
| ldap-radius | OpenLDAP (`slapd`) + FreeRADIUS 3.2 | `/etc/freeradius/3.0/` (sitio `default`, módulos `eap`, `ldap`, `rest`, `g05_intentos`); PKI en `certs-r1/` (CA, CRL, `ca-db/`, `clientes/`) | `infraestructura/files/r1-identidad.sh` | script en la VM (con `g05-bloqueo.py` en `/tmp/r1/`) |
| ldap-radius | **g05-bloqueo** (R1-03) | `/usr/local/sbin/g05-bloqueo`; estado en `/var/lib/g05/bloqueo.json`; lee `/var/log/freeradius/g05-intentos.log` | `infraestructura/files/g05-bloqueo.py` | `r1-identidad.sh` |
| ldap-radius | Secretos (RADIUS, LDAP, contraseñas) y certificados de prueba inválidos | `/root/g05-r1/` (solo root), `/root/g05-r1/pruebas/` | **no se versionan** | generados en la VM |
| dns-dhcp | Kea DHCPv4 con subred por rol y hook | `/etc/kea/` | `infraestructura/files/kea-dhcp4.conf`, `g05-kea-hook.sh` | `dhcp.yml` |
| recursos (y ldap-radius) | Servidores de prueba (`g05-svc`): banner por puerto; HTTP real en :80 con `/descarga?mb=N` | `/opt/g05/svc.py`, `svc.json` | `infraestructura/files/svc.py`, `servidores.sh` | `servicios.yml` |
| ids | Suricata 7 sobre la interfaz `ids-gre`; firmas `g05.rules` (R3) y `g05-r2.rules` (R2, generadas) | `/etc/suricata/g05.yaml`, `/etc/suricata/rules/` | `infraestructura/files/ids/` (`ids-setup.sh`, `g05.rules`, `g05-r2.rules`) | `ids-setup.sh`; `g05-r2.rules` con `r2ctl.py ids-reglas` |
| ids | ids-agent (`g05-ids-agent`): eve.json → identity | `/opt/g05/ids-agent.py` | `infraestructura/files/ids/ids-agent.py` | `ids-setup.sh` |
| alumno | Usuarios de prueba (namespaces + macvlan) y cliente 802.1X | `g05-usuarios.service`; `/usr/local/sbin/g05-r1`; certificados en `/etc/wpa_supplicant/pki/` | `politica/usuarios-ns.sh`, `politica/g05-r1.sh` | a mano (en el repo) |

---

## 5. Usuarios de prueba

| Namespace (VM Alumno) | MAC | Uso habitual |
|---|---|---|
| `u-inv` | 02:05:00:00:00:01 | Invitado (sin 802.1X) · **testigo** en R3/R4 |
| `u-alu` | 02:05:00:00:00:02 | **alu01** (alumno) · atacante en R3/R4 |
| `u-doc` | 02:05:00:00:00:03 | doc01 (docente) |
| `u-adm` | 02:05:00:00:00:04 | adm01 o multi01 |
| `u-net` | 02:05:00:00:00:05 | Invitado (atacante en el DDoS distribuido) |
| `u-cic` | 02:05:00:00:00:06 | Equipo que `r2ctl verify --roles all` pasa por los 6 roles |

| Usuario (LDAP) | Grupo(s) | Rol / VLAN |
|---|---|---|
| admin01 | net-admin | 5 / 500 |
| adm01 | net-administrativo | 4 / 400 |
| doc01 | net-docente | 3 / 300 |
| alu01 | net-alumno | 2 / 200 |
| **multi01** | net-docente **y** net-admin | 5 / 500 (multirol: gana el de mayor privilegio) |
| **prueba01** | net-alumno | 2 / 200 · solo para la prueba de bloqueo (R1-03) |
| sing01 | (ninguno) | Se rechaza |

**Certificados inválidos para pruebas** (en `/root/g05-r1/pruebas/` y en la `pki` de Alumno): `fantasma01` (no existe en LDAP), `alu01-caducado`, `alu01-revocado` (en la CRL), `alu01-ajena` (CA falsa).

```bash
sudo g05-r1 login <ns> <usuario> [certificado]   # en Alumno; el certificado es opcional
sudo g05-r1 dhcp <ns>
sudo g05-r1 logout <ns>
```

> La app AAA de ONOS admite **un supplicant autenticado por puerto**: un solo usuario 802.1X a la vez en el puerto de Alumno. Los invitados se dan de alta con `POST /identity/guest/<mac>` desde ONOS-1.

---

## 6. Cómo funciona cada requerimiento (y dónde mirar)

- **R1:**
  - **Flujo:** supplicant → app AAA de ONOS → FreeRADIUS (TLS: CA, CRL, CN = usuario) → LDAP (existe, no bloqueado, grupo) → `post-auth` envía usuario y VLAN a identity → AAA aprueba el puerto → identity crea la sesión → DHCP con la VLAN del rol → reglas.
  - **Rechazo uniforme:** todos los rechazos son iguales hacia el cliente; el motivo real queda en `radius.log`.
  - **Bloqueo:** 5 fallos en 15 min → `pwdAccountLockedTime` en LDAP (`g05-bloqueo`).
- **R2:**
  - **Política:** `politica/policy.yaml`. `r2ctl.compile_all` la compila a 6 tablas OpenFlow en R-SW1: T0 ingreso, T1 anti-spoofing, T2 mitigación, T3 rol, T4 política, T5 salida.
  - **Reconciliación:** identity la aplica por la REST de ONOS (appId `edu.pucp.r2ctl`) en cada evento.
  - **Decisión:** `r2ctl.evaluate_access`. Lo no registrado se deniega, y `deniega:` gana sobre cualquier permiso.
  - **Registro de accesos:** permitidos y denegados, vía las firmas generadas con `r2ctl ids-reglas`.
- **R3:**
  - **Detección:** el espejo GRE del puerto de usuarios llega a Suricata; eve.json → ids-agent → `POST /identity/alert`.
  - **Bloqueo:** regla T2 de descarte (prioridad 40000, 300 s) sobre la MAC autenticada; a la 3.ª alerta en 10 min, cuarentena (rol 9).
  - **Spoofing interno:** lo detecta el contador de la regla T1 (3 paquetes en 10 s).
- **R4:** identity lee los contadores de ONOS cada 2,5 s (`ddos.Detector`).
  - **Fuente:** usuario por encima de 50 Mbit/s, o que aporta más de 10 Mbit/s a un recurso que recibe más de 80, y que envía más de lo que recibe.
  - **Límite:** meter propio de 2 Mbit/s en T2 (prioridad 39000); se levanta tras 30 s de calma.
- **Registro de seguridad común:**
  - `GET /identity/incidents?desde=<epoch>` (archivo `/var/log/g05/incidentes.jsonl`).
  - Resumen en tabla: `bash pruebas/incidentes.sh <minutos>`.

---

## 7. Cómo se prueba (todo desde el repo)

| Qué | Comando (desde la raíz del repo) | Tiempo |
|---|---|---|
| Pruebas unitarias (125; las 11 del slice se omiten sin canales) | `python3 -m pytest pruebas/unitarias -v` | 30 s |
| Restaurar el slice antes de una demo | `bash pruebas/reset-demo.sh` | 40 s |
| R1: accesos inválidos, latencia, auth/s | `bash pruebas/prueba-r1.sh invalidos 3 \| latencia 12 \| carga` | 6 / 4 / 1 min |
| R2: matriz + trazabilidad | `bash pruebas/prueba-r2-trazabilidad.sh` | 5 min |
| R2: escalabilidad (detiene identity un rato) | `bash pruebas/prueba-r2-escala.sh` | 6 min |
| R3: 8 ataques + falsos positivos | `bash pruebas/prueba-r3.sh` | 7 min |
| R3: carga del IDS | `bash pruebas/carga-ids.sh` | 4 min |
| R4: DDoS de una fuente y distribuido | `bash pruebas/prueba-r4.sh` | 8 min |
| Fallas de enlaces y de Core-1 / caída de DF1 | `bash pruebas/prueba-fallas.sh` / `prueba-caida-df1.sh` | — |
| Regenerar los dos PDF | `python3 documentacion/generar_informe.py` y `generar_informe_previo.py` | 10 s |

Las pruebas que usan pytest y reportlab corren con el venv de `Proyecto-R2` (Python 3.9). Hace falta `pip install pytest pytest-cov pyyaml "reportlab<4.3" pypdf`.

---

## 8. Lo que aprendimos del VNRT (y cómo se resolvió)

| Hallazgo | Solución |
|---|---|
| No propaga la caída de portadora (el otro extremo sigue `LIVE`) | BFD (100 ms) decide la vida de cada enlace; grupos Fast Failover |
| Descarta la MAC de grupo de EAPOL (01:80:c2:00:00:03) | `g05-r1` reescribe el EAPOL saliente a broadcast con `tc` |
| No entrega al IDS el unicast ajeno por el enlace directo | Espejo de R-SW1 en **GRE** por la red de gestión |
| Puede perder el EAP-Failure hacia el cliente | El acceso lo decide identity (sin sesión no hay IP ni reglas) |
| Las VMs no tienen Internet | `apt-get download` en ONOS-1 + `dpkg -i`; imágenes con `docker save \| ssh \| docker load` |
| ONOS-1 tiene un disco de 5,9 GB, casi lleno con las imágenes | Vigilar `df -h /`; `apt-get clean` y `journalctl --vacuum-size`. `reset-demo.sh` avisa si quedan menos de 200 MB |
| La app AAA mantiene un supplicant por puerto | Pruebas con un usuario 802.1X a la vez + invitados |
| ONOS lee las estadísticas cada 5 s | Los detectores por contadores (spoofing interno, R4) tienen esa resolución |
| El Python 3.12 de las VMs no es el 3.9 de la Mac | Probar en el slice lo que escribe a disco (ver el problema del 24/11 abajo) |

---

## 9. Problemas encontrados y corregidos (cronología)

1. **Bootstrap del compañero:**
   - faltaba `--no-wait` en el ensayo;
   - la verificación leía siempre el puerto 1;
   - fallaba `iface-to-br br0`;
   - `dl_vlan=0xffff` reinstalaba las reglas cada 10 s.
2. **R3:** Suricata no veía los ataques porque el VNRT filtraba el unicast. Se pasó a un espejo en GRE.
3. **R3:** el servidor de prueba no confirmaba el HTTP, y el IDS veía las peticiones 70 s tarde. Ahora responde HTTP real.
4. **Redundancia:** con el enlace Core-1↔Core-2 caído, Core-2 perdía el camino a ONOS-2. R-SW2 ahora usa su enlace directo (grupo 50002). Lo encontró una prueba unitaria y está comprobado en el slice.
5. **R1-02:** un usuario inexistente se rechazaba distinto que un certificado inválido, y eso permitía enumerar cuentas. Ahora la comprobación va en `post-auth` y el rechazo lleva EAP-Failure.
6. **R2-02:** un rol desconocido lanzaba `KeyError`. `evaluate_access` ahora lo deniega por defecto.
7. **R3-03:** `hping3 -c 3` no se detectaba, porque ONOS repartía los paquetes en dos lecturas. El sensor usa ahora una ventana de 10 s.
8. **24/11 · sesiones que no sobrevivían a un reinicio de identity:**
   - **Causa:** el disco de ONOS-1 se llenó (100 %), y `sessions.json` quedaba en 0 bytes porque el error de escritura se perdía en silencio.
   - **Disco:** se liberaron 465 MB con `apt-get clean`.
   - **Código:** `identity.py` y `g05-bloqueo.py` ahora escriben con `with` + `fsync`, así que un fallo de escritura ya no pasa desapercibido.
   - **Comprobación:** tras reiniciar, identity arranca con la sesión y el usuario conserva el acceso.

---

9. **24/11 (tarde) · el disco de ONOS-1 se volvió a llenar:**
   - **Causa:** `unattended-upgrades` (ONOS-1 es la única VM con Internet) bajó 130 paquetes de seguridad (331 MB). No se instalaron.
   - **Arreglo:** se liberó la caché (`apt-get clean`, quedan ~420 MB) y **se desactivaron las actualizaciones automáticas de ONOS-1** hasta después de la sustentación.
   - **Para reactivarlas:** `sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer`.
10. **24/11 · alu01 bloqueado:** un `wpa_supplicant` con el certificado revocado quedó corriendo y reintentaba cada 60 s. Al 5.º fallo, R1-03 bloqueó la cuenta, como debe. Después de un login inválido, siempre `sudo g05-r1 logout <ns>`.

## 10. Pendientes y recomendaciones

- **Reactivar las actualizaciones automáticas de ONOS-1** después de la sustentación (ver el punto 9 de la sección anterior).

- **Limitar el tamaño del journal en ONOS-1** (por ejemplo `SystemMaxUse=50M` en journald) para que el disco no se vuelva a llenar.
- **Bajar `flowPollFrequency` de ONOS a 2 s** para acortar el spoofing interno y R4 a la mitad (a cambio de carga en el controlador).
- **Llevar el espejo del IDS a una red propia** (hoy comparte la de gestión con el clúster): evita que un flood grande afecte a Atomix.
- **Reconciliación incremental en identity:** hoy compara todas las reglas en cada cambio (O(sesiones)).
- **Prueba física de DC-DIST:** no se apagó la VM. Es el único camino in-band hacia ONOS-1; la teoría y la caída de DF1 dicen que ONOS-2 toma el control.
- **`r2-demo/`** es el slice anterior (4 switches): solo referencia.

---

## 11. Historial del repositorio (main)

| Commit | Contenido |
|---|---|
| `5dcc095` | Infraestructura in-band con redundancia del control |
| `3b12d9a` | DHCP de alumnos (VLAN 200/111, relay en Core-1, Kea) |
| `f0e7346` | Clúster ONOS-1 + ONOS-2 sobre Atomix en tres dominios de falla |
| `1a29138` | R2 en la topología final (política en R-SW1, Core-1 router) |
| `d6a6219` | R1: 802.1X EAP-TLS con roles por LDAP |
| `2b0b64d` | R3: Suricata con espejo GRE y mitigación por ONOS |
| `41b22c6` | R1: métricas, CRL y registro de intentos fallidos |
| `11724cc` | R2: trazabilidad de intentos y escalabilidad |
| `b62575b` | 69 pruebas unitarias + corrección del respaldo de R-SW2 |
| `4b1a1bd` | R4: DDoS por ancho de banda con meter por fuente |
| `495caf5` | Lab 7: 12 pruebas obligatorias, R1-03, multirol, evaluate_access, deniega, registro de accesos |
| `d9b430c` | Sensor de spoofing con ventana de 10 s |
| `90914fb` | Informe EXP_TEL354_LAB7_G5 y su generador |
| `e3b9a6a` | Informe previo y cobertura de código |
| `ffdb5ef` | `.gitignore` de `.coverage` |

**Nunca subir:** `credentials/`, `.netrc`, claves (`*.key`) ni nada de `/root/g05-r1`. El `.gitignore` ya los excluye.
