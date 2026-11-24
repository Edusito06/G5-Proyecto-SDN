# Guion de la sustentación en vivo · Lab 7 · G05

**Formato:** 30 minutos = 20 de demostración en vivo + 10 de preguntas. Lo que no se demuestra en vivo cuenta como no implementado.

**Qué exige la experiencia:** R1 (acceso de usuarios válidos), R2 (recursos privilegiados) y **R3** (requerimiento específico del G05). En el R3 hay que **generar el ataque desde un equipo de la topología** y mostrar tres cosas: la **alerta**, la **regla instalada en el switch** y el **registro del incidente**. R4 es adicional: se muestra solo si sobra tiempo.

Todos los comandos se ejecutan desde la Mac de Eduardo, con los canales SSH abiertos. Todos están probados en el slice.

---

## 0. Antes de entrar (la noche anterior y 15 min antes)

1. **VPN de la PUCP conectada.** Comprobar que la ruta al gateway sale por la VPN (`utun`), no por `en0`:

   ```bash
   route -n get 10.20.12.7 | grep interface
   ```

2. **Abrir los 10 canales SSH.** Cada uno pide su contraseña. Si cambiaste de red, primero cierra los viejos: este comando ya lo hace.

   ```bash
   for p in 22 5800 5801 5803 5804 5806 5809 5811 5812 5813; do ssh -S ~/.ssh/ctl-$p -O exit ubuntu@10.20.12.7 2>/dev/null; rm -f ~/.ssh/ctl-$p; ssh -fN -M -S ~/.ssh/ctl-$p -p $p ubuntu@10.20.12.7; done
   ```

3. **Restaurar el slice.** Cierra sesiones y levanta bloqueos, límites, cuarentenas y cuentas bloqueadas. Comprueba los servicios, el clúster y el **disco de ONOS-1**. Anota la marca `desde=` que imprime al final.

   ```bash
   bash pruebas/reset-demo.sh
   ```

   Debe terminar con `clúster ONOS: 192.168.0.16 READY, 192.168.0.17 READY` y `switches disponibles: 6 de 6`. Si avisa poco disco:

   ```bash
   ssh -S ~/.ssh/ctl-5806 x@10.20.12.7 'sudo apt-get clean; sudo journalctl --vacuum-size=30M; df -h /'
   ```

4. **Pruebas unitarias.** Tardan unos 30 s; deben dar `125 passed`. Dejar la salida en pantalla para el cierre.

   ```bash
   ../Proyecto-R2/.venv/bin/python -m pytest pruebas/unitarias -q
   ```

5. **Abrir los PDF** `documentacion/EXP_TEL354_LAB7_G5.pdf` (figuras 1 y 2) e `INFORME_PREVIO_TEL354_LAB7_G5.pdf`.

### Las 4 ventanas de la demo

Pegar en **cada** terminal esta línea de funciones:

```bash
GW=10.20.12.7; c() { ssh -S ~/.ssh/ctl-$1 x@$GW "${@:2}"; }; ct() { ssh -t -S ~/.ssh/ctl-$1 x@$GW "${@:2}"; }; alumno() { c 5813 "$@"; }; onos1() { c 5806 "$@"; }
```

| Ventana | Qué muestra | Comando |
|---|---|---|
| **1 · Registro de identity** | Sesiones, alertas, bloqueos, intentos y accesos, en vivo | `ct 5806 'sudo journalctl -fu g05-identity -o cat \| grep --line-buffered -v REGLAS'` |
| **2 · Switch R-SW1** | Tabla 2 (mitigación) y meters, cada segundo | `ct 5803 'watch -n1 "sudo ovs-ofctl -O OpenFlow13 dump-flows br0 table=2 \| cut -c1-160; sudo ovs-ofctl -O OpenFlow13 dump-meters br0"'` |
| **3 · FreeRADIUS** | Cada intento de login con su motivo | `ct 5809 'sudo tail -f /var/log/freeradius/radius.log'` |
| **4 · Atacante / usuario** | Donde se escriben los comandos de la demo | (la línea de funciones de arriba) |

> **Regla de oro:** la app AAA de ONOS admite **un usuario 802.1X a la vez** en el puerto de la VM Alumno. Antes de cada login, cierra la sesión anterior: `alumno 'sudo g05-r1 logout <ns>'`. Los invitados no usan 802.1X y pueden convivir con él.

---

## Bloque 1 · Arquitectura y plano de control (0:00 – 2:00)

**Qué mostrar:** la figura 2 del PDF (topología) y la figura 1 (arquitectura).

**Qué decir:**
- 15 VMs en tres dominios de falla.
- 6 switches OVS controlados **in-band**: el canal OpenFlow viaja por los mismos enlaces de datos.
- Clúster de **2 nodos ONOS sobre 3 de Atomix** (Raft: con 2 de 3 votos hay quórum).
- BFD + Fast Failover protegen el canal de control sin depender de ONOS.

**Comando (ventana 4):** muestra el clúster, los switches y quién es el master de R-SW1.

```bash
onos1 'curl -sn localhost:8181/onos/v1/cluster | python3 -m json.tool | grep -E "\"ip\"|status"; curl -sn localhost:8181/onos/v1/devices | python3 -c "import json,sys; [print(d[\"id\"], \"disponible\" if d[\"available\"] else \"CAÍDO\", d[\"annotations\"][\"managementAddress\"]) for d in json.load(sys.stdin)[\"devices\"]]"; curl -sn localhost:8181/onos/v1/mastership/of:0000000000000006/role'
```

**Qué debe verse:**
- dos nodos `READY` (192.168.0.16 y .17);
- 6 switches `disponible` con IPs **10.100.0.3–.8**, que son las IPs in-band;
- el master de R-SW1.

> Si el jurado pide la consola de ONOS (`nodes`, `devices`, `summary`), es `ct 5806 'sudo docker exec -it onos /root/onos/apache-karaf-4.2.9/bin/client'` con el usuario de karaf que configuraron. **Pruébenlo antes**: la REST de arriba muestra lo mismo.

---

## Bloque 2 · R1: autenticación, roles y multirol (2:00 – 6:00)

**2.1 Usuarios y roles almacenados (LDAP).** Al decirlo:
- 6 roles; el rol es el grupo LDAP y viaja como VLAN = rol × 100.
- La credencial es un certificado X.509 (EAP-TLS).

```bash
c 5809 'sudo ldapsearch -x -LLL -H ldap://localhost -D cn=admin,dc=campus,dc=lab -y /root/g05-r1/ldap_admin -b ou=groups,dc=campus,dc=lab member | grep -E "^(dn|member)"'
```

**2.2 Flujo de un usuario válido.**

```bash
alumno 'sudo g05-r1 login u-alu alu01; sleep 2; sudo g05-r1 dhcp u-alu'
```

Debe verse:
- **Ventana 3:** `Login OK: [alu01]`.
- **Ventana 1:** `RADIUS_ACEPTADO vlan 200` → `SESION_AUTORIZADA rol 2` → `VINCULADO ip 10.20.0.x`.
- **Ventana 4:** IP `10.20.0.x/24`, la subred del alumno.

**2.3 Flujo de un usuario inválido.** Primero el certificado revocado, luego el usuario sin grupo:

```bash
alumno 'sudo g05-r1 logout u-alu; sudo g05-r1 login u-alu alu01 alu01-revocado; sudo g05-r1 dhcp u-alu'
```

```bash
alumno 'sudo g05-r1 logout u-alu; sudo g05-r1 login u-alu sing01; sudo g05-r1 dhcp u-alu'
```

Debe verse:
- **Ventana 3:** `Login incorrect (... certificate revoked)` y `Login incorrect (usuario sin grupo de red)`.
- **Ventana 4:** el DHCP no da IP.

> ⚠️ **Después de un login inválido, siempre `logout`.** Un `wpa_supplicant` rechazado no se detiene: reintenta cada ~60 s, y cada intento cuenta como fallo. A los 5 min la cuenta (por ejemplo alu01) queda **bloqueada 15 min** por R1-03. Si pasa: `bash pruebas/reset-demo.sh`.

**Qué decir:** el VNRT puede perderse el EAP-Failure, y por eso el supplicant de sing01 puede decir "Success". Lo que decide el acceso es identity: sin sesión no hay ni IP ni reglas. Además, todos los rechazos son **idénticos** hacia el cliente, así que no se puede saber si una cuenta existe. Eso lo prueba R1-02.

**2.4 Soporte multirol.** multi01 está en los grupos docente y admin:

```bash
alumno 'sudo g05-r1 logout u-alu; sudo g05-r1 login u-adm multi01; sleep 2; sudo g05-r1 dhcp u-adm'
```

**Ventana 1:** `SESION_AUTORIZADA usuario multi01 rol 5`. Gana el de mayor privilegio, y obtiene una IP `10.50.0.x`.

**2.5 Bloqueo al 5.º intento fallido (R1-03).** Se corre la prueba contra el FreeRADIUS real con el usuario de prueba `prueba01`, y lo desbloquea al terminar (~15 s):

```bash
../Proyecto-R2/.venv/bin/python -m pytest pruebas/unitarias/test_lab7_slice.py -k R1_03 -v
```

Luego mostrar el registro del bloqueo: `FALLO 1…4 bloqueado false`, `FALLO 5 bloqueado true`, `BLOQUEO hasta …`.

```bash
c 5809 'sudo journalctl -u g05-bloqueo -n 9 -o cat'
```

---

## Bloque 3 · R2: autorización y denegación por flows (6:00 – 9:30)

Seguimos con **multi01 (admin)** del paso 2.4.

**3.1 Flujo de autorización** a Matrícula (recurso crítico):

```bash
alumno 'sudo ip netns exec u-adm nc -zv -w2 10.100.0.50 443'
```

**Ventana 1:** `ACCESO_PERMITIDO usuario multi01 ... admin -> G04 matricula`. Para ver el **flow de permiso** en el switch:

```bash
c 5803 'sudo ovs-ofctl -O OpenFlow13 dump-flows br0 table=4 | grep -E "dl_vlan=500" | sed -E "s/ ?(duration|idle_age)=[^,]*,//g"'
```

**3.2 Flujo de denegación:** el alumno intenta Matrícula y Notas.

```bash
alumno 'sudo g05-r1 logout u-adm; sudo g05-r1 login u-alu alu01; sleep 2; sudo g05-r1 dhcp u-alu; sudo ip netns exec u-alu nc -zv -w2 10.100.0.50 443; sudo ip netns exec u-alu nc -zv -w2 10.100.0.130 443'
```

Debe verse:
- Las dos conexiones fallan.
- **Ventana 1:** `INTENTO_DENEGADO usuario alu01 ... alumno -> G04 matricula` y `... G06 notas`, con su MAC y destino.
- El **flow de denegación**, con el comando de abajo: `priority=23000 ... nw_dst=10.100.0.0/25 actions=meter:2,CONTROLLER` (bloque crítico) y `priority=22000 ... drop` (intranet).

```bash
c 5803 'sudo ovs-ofctl -O OpenFlow13 dump-flows br0 table=4 | grep -E "dl_vlan=200" | sed -E "s/ ?(duration|idle_age)=[^,]*,//g"'
```

**3.3 Cambio de política en caliente.** Necesita a doc01 en sesión; si no hay tiempo, este paso se puede omitir.

```bash
alumno 'sudo g05-r1 logout u-alu; sudo g05-r1 login u-doc doc01; sleep 2; sudo g05-r1 dhcp u-doc; sudo ip netns exec u-doc nc -zv -w2 10.100.0.146 443'
```

La conexión a Investigación (G07) **pasa**. Ahora se revoca G07 al docente en caliente, con `deniega` sobre un recurso que tiene permitido (DENY gana):

```bash
onos1 'P=/opt/g05/politica/policy.yaml; sudo cp $P /tmp/policy.antes; sudo sed -i "s/^  3: {nombre: docente,        permite: \[G06, G07, G08, G10, G11, G12\], internet: true}/  3: {nombre: docente,        permite: [G06, G07, G08, G10, G11, G12], deniega: [G07], internet: true}/" $P; sudo systemctl restart g05-identity'
```

```bash
alumno 'sleep 5; sudo ip netns exec u-doc nc -zv -w2 10.100.0.146 443'; c 5803 'sudo ovs-ofctl -O OpenFlow13 dump-flows br0 table=4 | grep priority=29950'
```

Ahora **falla**, y aparece `priority=29950,ip,dl_vlan=300,nw_dst=10.100.0.144/28 actions=drop`. **Volver a la política original:**

```bash
onos1 'sudo cp /tmp/policy.antes /opt/g05/politica/policy.yaml; sudo systemctl restart g05-identity'
```

**Qué decir:** identity guarda las sesiones en disco, así que al reiniciarse vuelve a instalar las reglas de doc01 con la política nueva y doc01 no pierde la sesión. La precedencia en T4 es deniega 29950 > permiso total 29900 > permisos 25000 > crítico 23000 > intranet 22000 > Internet 21000.

---

## Bloque 4 · R3: ataques encubiertos (9:30 – 16:00) ← el más importante

**Preparación:**
- **Atacante:** alu01 en `u-alu`.
- **Testigo legítimo:** un invitado en `u-inv`, en el **mismo puerto** del switch. Sirve para demostrar que solo se bloquea al atacante.

```bash
alumno 'sudo g05-r1 logout u-doc; sudo g05-r1 login u-alu alu01; sleep 2; sudo g05-r1 dhcp u-alu'; onos1 'curl -s -X POST localhost:5001/identity/guest/02:05:00:00:00:01'; alumno 'sleep 3; sudo g05-r1 dhcp u-inv'
```

Para ver si alguien llega a su recurso (Portal para el alumno, Mesa de ayuda para el invitado), pegar esta función en la ventana 4:

```bash
acceso() { alumno "sudo ip netns exec u-alu timeout 2 nc -z -w1 10.100.1.10 443 && echo 'alu01 -> Portal: sí' || echo 'alu01 -> Portal: NO'; sudo ip netns exec u-inv timeout 2 nc -z -w1 10.100.1.150 80 && echo 'invitado -> Mesa de ayuda: sí' || echo 'invitado -> Mesa de ayuda: NO'"; }
```

Para levantar el bloqueo entre un ataque y otro: borra el bloqueo **y** el historial de alertas, así no pasa a cuarentena. Esperar 9 s.

```bash
levantar() { onos1 'curl -s -X DELETE localhost:5001/identity/block/02:05:00:00:00:02'; sleep 9; }
```

**4.1 Tráfico legítimo sin bloqueo** (criterio 8 de R3): 15 conexiones a puertos ofrecidos, por debajo del umbral.

```bash
alumno 'for i in 1 2 3; do for p in 80 443; do sudo ip netns exec u-alu timeout 2 nc -z -w1 10.100.1.150 $p; done; sudo ip netns exec u-alu timeout 2 nc -z -w1 10.100.1.10 443; done; echo listo'; acceso
```

Ningún `ALERTA_IDS` ni `BLOQUEO`. Solo aparecen `ACCESO_PERMITIDO`.

**4.2 Ataque 1: escaneo de puertos.**

```bash
alumno 'sudo ip netns exec u-alu nmap -sS -Pn -n -T4 --max-retries 0 -p 1000-1100 10.100.1.150 | tail -2'; acceso
```

Debe verse, y hay que señalarlo en orden:
- **(a) La alerta** (ventana 1): `ALERTA_IDS firma "G05 R3 escaneo de puertos" src_ip 10.20.0.x dst 10.100.1.150:… usuario alu01`.
- **(b) La regla** (ventana 2): `priority=40000,in_port=4,dl_src=02:05:00:00:00:02 actions=drop` en la **tabla 2** de R-SW1.
- **(c) El efecto:** `alu01 -> Portal: NO` mientras `invitado -> Mesa de ayuda: sí`, en el mismo puerto físico.
- **(d) El registro:** `BLOQUEO ... accion REGLA_T2_DROP ttl 300` y luego `MITIGACION_APLICADA ms ~150`.

**Qué decir:**
- Umbral: más de 10 SYN a puertos no ofrecidos en 5 s.
- Se bloquea la **MAC autenticada**, no la IP, que puede falsificarse.
- La alerta llega en decenas de ms y ONOS aplica la regla en ~150 ms.

```bash
levantar
```

**4.3 Ataque 2: escaneo de red.**

```bash
alumno 'sudo ip netns exec u-alu nmap -sn -PS80 -n -T4 10.30.0.0/26 | tail -1'; acceso
```

Debe verse `ALERTA_IDS ... escaneo de red (destinos fuera de los servicios)` → `BLOQUEO`.

```bash
levantar
```

**4.4 Ataque 3: IP spoofing.** Primero externo (lo detecta el IDS con 1 paquete), luego interno (lo detecta el sensor del switch: 3 paquetes en 10 s).

```bash
alumno 'sudo ip netns exec u-alu hping3 -c 3 -S -a 198.51.100.7 -p 80 10.100.1.150 2>&1 | tail -1'; acceso; levantar
```

```bash
alumno 'sudo ip netns exec u-alu hping3 -c 3 -S -a 10.20.0.77 -p 80 10.100.1.150 2>&1 | tail -1'; sleep 6; acceso
```

Debe verse:
- **Externo:** `ALERTA_IDS ... IP spoofing (origen fuera de las subredes del campus)`.
- **Interno:** `BLOQUEO ... "IP spoofing (3 paquetes en 10 s)" fuente switch`.

**Qué decir:** la terna puerto + MAC + IP está en la tabla 1, así que el paquete falso nunca sale del switch. Su contador es el sensor.

```bash
levantar
```

**4.5 (opcional) Request malicioso:** inyección SQL.

```bash
alumno "sudo ip netns exec u-alu curl -s -m2 'http://10.100.1.150/buscar?q=1%20UNION%20SELECT%20usuario,clave%20FROM%20cuentas'"; sleep 1; acceso; levantar
```

**4.6 Registro consolidado de incidentes.** Una fila por incidente: hora, usuario, MAC, IP de origen, fuente (IDS o switch), firma, retardo del agente, ms hasta la regla, cierre y duración.

```bash
bash pruebas/incidentes.sh 10
```

**4.7 Expiración y recuperación.** El bloqueo vence solo a los **300 s** (`BLOQUEO_VENCIDO accion REGLA_T2_RETIRADA`). En la demo lo levantamos a mano. Lo prueba la ficha 3.2.1.

**Qué decir:**
- A la **3.ª alerta en 10 min** el usuario pasa a **cuarentena**: rol 9, VLAN 900, solo DNS y Mesa de ayuda.
- Para mostrarla, lanzar tres ataques **sin** `levantar` entre ellos.

---

## Bloque 5 · R4 adicional: DDoS (16:00 – 18:30) · solo si hay tiempo

Inundación ACK con carga útil de alu01, 60 s a ~10 000 pps. No tiene firma en R3. **No usar `--flood` sin límite:** el espejo del IDS copia ese tráfico por la red de gestión, que también usa el clúster.

```bash
levantar; alumno 'sudo ip netns exec u-alu timeout 60 hping3 -q -A -p 80 -d 1200 -i u100 10.100.1.150 >/dev/null 2>&1 &'
```

En unos **12–15 s**:
- **Ventana 1:** `DDOS_DETECTADO usuario alu01 motivo volumétrico bps ~77 Mbit/s meter N`.
- **Ventana 2:** `meter=N kbps ... rate=2000` y la regla `priority=39000 ... actions=meter:N,goto_table:3`.

El testigo sigue descargando a cientos de Mbit/s:

```bash
alumno 'sudo ip netns exec u-inv curl -s -o /dev/null -w "testigo: %{speed_download} B/s\n" "http://10.100.1.150/descarga?mb=50"'
```

**Qué decir:**
- **No se bloquea, se limita:** la fuente queda en 2 Mbit/s con su propio meter.
- **No se confunde con una descarga:** una fuente debe enviar **más de lo que recibe**, y una descarga legítima no lo cumple.
- **Ataque distribuido:** si varias fuentes por debajo del umbral saturan un servidor (> 80 Mbit/s), se identifican las que aportan más de 10 Mbit/s.
- **Fin del ataque:** a los ~40 s aparece `LIMITE_LEVANTADO duracion_s …`.

---

## Bloque 6 · Métricas y cierre (18:30 – 20:00)

Mostrar la sección 7 del PDF de la experiencia y la salida de `pytest` (`125 passed`):

| | Resultado medido |
|---|---|
| R3 · detección | 8/8 ataques (100 %); 0 falsos positivos en 60 s de tráfico legítimo |
| R3 · tiempo hasta bloquear | 0,3–1,1 s con firma; 4,5–6 s el spoofing interno (sondeo de ONOS cada 5 s) |
| R3 · tiempo de mitigación | Agente 8–102 ms + regla en ONOS 144–166 ms (< 1 s) |
| R3 · carga del IDS | 400 sesiones maliciosas/s con 100 % de detección, 0 pérdidas y 10,5 % de CPU |
| R1 | 21/21 accesos inválidos bloqueados; EAP-TLS en 82 ms; ~33 auth/s; bloqueo al 5.º fallo |
| R2 | 216 pruebas, 0 discrepancias, 142/142 bloqueados; 53/53 intentos registrados con su usuario |
| Recursos | 72 reglas fijas + 7 por usuario; con 200 sesiones, 1 503 reglas, OVS al 1 % de CPU y 50 MB |
| Pruebas unitarias | 125 (12 obligatorias del Lab 7); 89,5 % de cobertura de la lógica de decisión |

**Frase de cierre:** las pruebas encontraron cinco defectos reales y los corregimos:
1. enumeración de cuentas;
2. KeyError ante un rol desconocido;
3. spoofing de 3 paquetes que no se detectaba;
4. pérdida del camino ONOS-2 → Core-2;
5. un servidor que confirmaba el HTTP tarde.

---

## Si algo falla en vivo

| Síntoma | Qué hacer |
|---|---|
| Un comando no responde | El canal se cayó: reabre ese puerto con el bucle del paso 0.2 |
| `EAP-Failure` o `sin respuesta` en un login válido | Había otra sesión 802.1X en el puerto: `alumno 'sudo g05-r1 logout <ns>'` y repetir |
| El atacante ya estaba bloqueado (`Portal: NO` antes del ataque) | Ejecutar `levantar` |
| Un usuario quedó en cuarentena (rol 9) | `onos1 'curl -s -X DELETE localhost:5001/identity/quarantine/<mac>'` y nuevo login |
| prueba01 quedó bloqueado | `bash pruebas/reset-demo.sh` |
| identity en "activating" | `onos1 'df -h /'`; si está lleno: `sudo apt-get clean; sudo journalctl --vacuum-size=30M` |
| Todo raro | `bash pruebas/reset-demo.sh` (~40 s) y repetir el escenario |
| Se cae ONOS-1 | Mostrar que ONOS-2 toma los 6 switches en ~11 s: es justamente la alta disponibilidad |

---

## Preguntas probables (10 min)

| Pregunta | Respuesta corta |
|---|---|
| ¿Por qué in-band y no out-of-band? | El slice no tiene una red de control separada (la de gestión es para SSH y el clúster). In-band con BFD + Fast Failover protege el canal localmente, sin depender de ONOS para conmutar. |
| ¿Qué pasa si cae ONOS-1? | Atomix mantiene quórum con 2 de 3. ONOS-2 asume la maestría de los 6 switches en ~11 s (medido). Los switches conservan sus reglas mientras tanto. |
| ¿Dónde hay un punto único de falla? | DC-DIST es el único camino in-band hacia ONOS-1, pero entonces ONOS-2 (por R-SW2) toma el control. El IDS es único: si cae, R3 pierde las firmas, pero siguen el anti-spoofing, el sensor del switch y R2. |
| ¿Por qué EAP-TLS y no usuario y contraseña? | No hay contraseñas que robar ni adivinar. El certificado ata la identidad (CN = usuario) y se puede revocar (CRL). |
| Entonces, ¿cómo hay bloqueo por intentos fallidos? | Cada Access-Reject es un fallo. g05-bloqueo cuenta 5 en 15 min y marca la cuenta en LDAP (`pwdAccountLockedTime`); FreeRADIUS la rechaza incluso con su certificado. |
| ¿Cómo evitan falsos positivos en R3? | Umbrales calibrados con la matriz de R2 y tráfico legítimo, solo sobre puertos no ofrecidos. Medido: 0 falsos positivos. |
| ¿Por qué bloquean la MAC y no la IP? | La IP se puede falsificar. La MAC está atada a la sesión 802.1X y al puerto, y el anti-spoofing de T1 impide usar otra. |
| ¿Cómo llega el tráfico al IDS? | Espejo OVSDB del puerto de usuarios de R-SW1, en un túnel GRE por la red de gestión. El VNRT no entregaba el unicast ajeno por el enlace directo. |
| ¿Cuánto escala? | 7 reglas por usuario en su switch de acceso; con 200 sesiones, 1 503 reglas y OVS al 1 % de CPU. El límite hoy es la reconciliación completa de identity. |
| ¿Cómo garantizan que las reglas hacen lo que dice la política? | Un oráculo (`evaluate_access`) decide desde `policy.yaml` y un simulador recorre las reglas compiladas: coinciden en las 216 combinaciones, y en el slice también. |

> La prueba de salida (5 pts) es sobre las **sesiones 13 y 14**: alta disponibilidad de ONOS, elección de líder, SPOF y arquitecturas. Repasen ese material. Nuestro clúster (Raft en Atomix, maestría por switch en ONOS) sirve de ejemplo concreto.
