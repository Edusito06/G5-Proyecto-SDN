#!/usr/bin/env python3
"""Genera el Informe Previo del Lab 7 (TEL354, G05) desde el repositorio.

Reutiliza estilos, diagramas y fichas de generar_informe.py. La cobertura sale de
documentacion/evidencia/cobertura*.txt y los resultados de pytest.txt.

Uso (desde la raíz del repo):
    python3 -m pytest pruebas/unitarias -v > documentacion/evidencia/pytest.txt
    python3 -m pytest pruebas/unitarias -q --cov=politica --cov=infraestructura/files \\
            --cov-report=term > documentacion/evidencia/cobertura.txt
    python3 documentacion/generar_informe_previo.py
"""
import re
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generar_informe as gi  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.units import cm  # noqa: E402
from reportlab.platypus import PageBreak, SimpleDocTemplate, Spacer  # noqa: E402

P, tabla, lista, codigo, S = gi.P, gi.tabla, gi.lista, gi.codigo, gi.S
SALIDA = gi.RAIZ / 'documentacion' / 'INFORME_PREVIO_TEL354_LAB7_G5.pdf'


def portada(story):
    story += [Spacer(1, 3.2 * cm), P('TEL354 · Redes Definidas por Software', 'sub'), Spacer(1, 6),
              P('Informe Previo · Laboratorio 7', 'tit'),
              P('Diseño, implementación y unit testing de los módulos del proyecto', 'sub'), Spacer(1, 1.2 * cm),
              P('Red de campus SDN con control in-band y alta disponibilidad', 'sub'),
              P('Módulos base R1 y R2 · requerimiento específico R3', 'sub'), Spacer(1, 1.6 * cm)]
    filas = [['Grupo', 'G05'], ['Integrantes', '<br/>'.join(gi.INTEGRANTES)], ['Profesor', 'Christian Quispe'],
             ['Jefe de práctica', 'William D. Lavado Gonzales'], ['Semestre', '2026-2'],
             ['Fecha', date.today().strftime('%d/%m/%Y')], ['Repositorio', f'<link href="{gi.REPO}">{gi.REPO}</link>']]
    story.append(tabla(filas, [4 * cm, 10 * cm], cab=False,
                       estilo_extra=[('BACKGROUND', (0, 0), (0, -1), gi.AZUL_C), ('FONTNAME', (0, 0), (0, -1), 'Arial-B')]))
    story.append(PageBreak())


# ============================================================ 1. Decisiones
def tecnologias(story):
    story.append(P('1. Análisis de decisiones y planteamiento de unit test', 'h1'))
    story.append(P('1.1 Selección de tecnologías', 'h2'))
    story.append(tabla([
        ['Componente', 'Elegida', 'Alternativas', 'Justificación'],
        ['Controlador SDN', 'ONOS 2.7 (Docker) en clúster', 'Ryu, OpenDaylight', 'Clúster nativo sobre Atomix (Raft), app AAA para 802.1X, REST completa de flujos, grupos y meters. Ryu no tiene clúster; ODL pesa más que la RAM disponible.'],
        ['Almacén del clúster', 'Atomix 3.1.5, 3 nodos', '2 nodos ONOS sin árbitro', 'Con 3 votantes en 3 dominios de falla, la caída de uno conserva quórum (2/3).'],
        ['Switches', 'Open vSwitch 3.3, OpenFlow 1.3', 'OF 1.0, OVSDB solo', 'Multitabla (pipeline de 6 tablas), meters y grupos Fast Failover.'],
        ['Canal de control', 'In-band + BFD + Fast Failover', 'Out-of-band', 'El slice no tiene una red de control aparte de la de gestión; in-band con respaldo local no depende del controlador para conmutar.'],
        ['Autenticación', '802.1X con EAP-TLS', 'Portal cautivo, PEAP/MSCHAPv2', 'Autenticación en el puerto antes de dar IP; sin contraseñas que robar; el certificado ata identidad y CN.'],
        ['Usuarios y roles', 'OpenLDAP 2.6 + FreeRADIUS 3.2', 'Base de datos / JSON', 'Estándar (RADIUS para el NAS de ONOS, grupos LDAP = roles, ppolicy para bloqueo).'],
        ['Direccionamiento', 'Kea DHCPv4 + dhcrelay en Core-1', 'ISC dhcpd', 'Subred por rol según la interfaz del relay; hook para avisar concesiones.'],
        ['IDS', 'Suricata 7 (AF_PACKET)', 'Snort, Zeek', 'Firmas con umbrales (detection_filter), EVE JSON con MAC y multihilo.'],
        ['Lógica propia', 'Python 3 (microservicios systemd)', 'App Java en ONOS', 'Iteración rápida, pruebas con pytest; la política se programa por la REST de ONOS.'],
        ['Automatización', 'Ansible + scripts idempotentes', 'Manual', 'El bootstrap in-band y la redundancia son repetibles; las VMs no tienen Internet.'],
    ], [2.6 * cm, 3.4 * cm, 2.8 * cm, 8.2 * cm]))
    story.append(P('1.2 Restricciones del sistema', 'h2'))
    story.append(tabla([
        ['Restricción', 'Efecto en el diseño'],
        ['Límite de VMs del slice (15) y ~1 GB de RAM real en DC-DIST, R-SW1, R-SW2 y S-DIST', 'Un switch por función, usuarios de prueba como namespaces en una sola VM (Alumno), Atomix-3 solo árbitro.'],
        ['Las VMs no tienen salida a Internet (solo ONOS-1 por NAT)', 'Paquetes .deb bajados en ONOS-1 e instalados con dpkg; imágenes Docker con docker save | ssh | docker load.'],
        ['El VNRT no propaga la caída de portadora', 'La vida de cada enlace la decide BFD (100 ms), no el estado del puerto.'],
        ['El VNRT descarta la MAC de grupo de EAPOL y el unicast ajeno hacia el IDS', 'tc reescribe el EAPOL a broadcast; el espejo hacia el IDS viaja en GRE por la red de gestión.'],
        ['La app AAA de ONOS mantiene un supplicant autenticado por puerto', 'Las pruebas usan un usuario 802.1X a la vez por puerto (más invitados sin 802.1X).'],
        ['ONOS lee las estadísticas de flujos cada 5 s', 'Los detectores por contadores (spoofing interno, R4) tienen esa resolución.'],
        ['Disco de ONOS-1 de 5,9 GB', 'Imágenes de ONOS y Atomix ajustadas; se vigila df antes de cada cambio.'],
    ], [7.2 * cm, 9.8 * cm]))


def despliegue(story):
    story.append(P('1.3 Despliegue y mantenimiento de la solución', 'h2'))
    story.append(P('Modelo: <b>microservicios sobre el sistema operativo</b> (systemd) alrededor de un <b>controlador '
                   'en contenedores</b> (ONOS y Atomix en Docker con red del host). Cada servicio tiene una sola '
                   'responsabilidad, se comunica por REST y guarda su estado en disco.', 'n'))
    story.append(tabla([
        ['Contexto', 'Cómo se gestiona'],
        ['Despliegue inicial', 'Ansible desde el Gateway: bootstrap in-band (paper.yml), redundancia (redundancia.yml), servicios (servicios.yml) y clúster (cluster.yml). Luego r1-identidad.sh (LDAP, RADIUS, PKI, bloqueo), ids-setup.sh e instalar-identity.sh.'],
        ['Operación normal (día a día)', 'identity reconcilia las reglas en cada evento (login, DHCP, alerta, límite). Monitoreo: GET /identity/sessions, /incidents, /trafico; ovs-ofctl dump-flows y dump-meters en R-SW1; pruebas/incidentes.sh para el registro consolidado. Los bloqueos y límites vencen solos.'],
        ['Actualización de un módulo (mantenimiento)', '1) correr las pruebas unitarias; 2) copiar el archivo al gateway y a su VM; 3) reiniciar solo su servicio (systemctl restart g05-identity, g05-bloqueo, suricata…); 4) verificar con la prueba funcional del módulo. Las sesiones persisten (sessions.json) y identity reinstala las reglas al arrancar. Cambios de FreeRADIUS: freeradius -C antes de reiniciar y copia de respaldo del sitio para volver atrás.'],
        ['Contingencia', 'Caída de ONOS-1/Atomix-1 (DF1): ONOS-2 toma los 6 switches en ~11 s. Caída de un enlace o de Core-1: BFD + Fast Failover, sin cortar sesiones. Política: los switches conservan sus reglas aunque identity se reinicie.'],
    ], [3.8 * cm, 13.2 * cm]))
    story.append(PageBreak())


# ============================================================ 2. Módulos
def modulo_r1(story):
    story.append(P('2. Descripción y justificación de los módulos', 'h1'))
    story.append(P('2.1 Módulo 1 (R1): control de acceso de usuarios válidos según su rol', 'h2'))
    story.append(P('<b>Objetivo.</b> Que solo un usuario válido, autenticado en el puerto por 802.1X, obtenga IP y '
                   'acceso, y que lo haga con el rol que le corresponde.', 'n'))
    story.append(tabla([
        ['Criterio del proyecto', 'Tipo', 'Cómo lo resuelve el módulo'],
        ['% de accesos inválidos bloqueados', 'Cuantitativo', 'EAP-TLS + CN = identidad + CRL + grupo LDAP obligatorio; sin sesión en identity no hay DHCP ni reglas.'],
        ['Latencia de autenticación', 'Cuantitativo', 'Intercambio EAP-TLS medido de punta a punta; las reglas se instalan al aprobar la sesión.'],
        ['Logins por segundo', 'Cuantitativo', 'FreeRADIUS local + LDAP; identity agrupa los cambios que llegan juntos.'],
        ['Escalabilidad de roles', 'Cuantitativo', 'Un rol = grupo LDAP + VLAN + subred; la política crece con roles × recursos, no con usuarios.'],
        ['Usuarios almacenados, roles (≥ 3), asignación y multirol', 'Cualitativo', 'OpenLDAP (ou=people, grupos net-*); 6 roles; el de mayor privilegio gana.'],
        ['Intentos fallidos registrados y bloqueo', 'Cualitativo', 'radius.log con el motivo, registro de seguridad de identity y g05-bloqueo (5 fallos en 15 min).'],
    ], [5 * cm, 2.4 * cm, 9.6 * cm]))
    story.append(P('Funciones', 'h3'))
    story.append(tabla([
        ['Función (archivo)', 'Responsabilidad'],
        ['FreeRADIUS authorize / authenticate / post-auth (r1-identidad.sh)', 'Valida el certificado (CA, CRL, CN = identidad), consulta LDAP, decide el rol (VLAN) y rechaza de forma uniforme.'],
        ['identity.take_radius / on_approved', 'Une la respuesta de RADIUS (usuario, VLAN) con la aprobación de AAA (puerto, MAC): crea la sesión.'],
        ['identity.on_dhcp', 'Vincula la IP solo si está en la subred del rol; libera al vencer la concesión.'],
        ['identity.finalize / vencer / watch_logoff', 'Cierra sesiones (logoff, reautenticación vencida) y retira sus reglas.'],
        ['g05-bloqueo.register_failed_attempt / register_success / is_locked / vencidos', 'Bloqueo por intentos fallidos con ventana y duración; desbloqueo automático.'],
        ['g05-bloqueo.leer_linea / procesar', 'Lee los resultados de FreeRADIUS (usuario en hexadecimal) y descarta entradas maliciosas.'],
    ], [6.4 * cm, 10.6 * cm]))
    pasos = [('Supplicant: EAPOL-Start en R-SW1 (puerto 4)', '#FFF7E6'),
             ('ONOS AAA: EAP ⇄ RADIUS hacia FreeRADIUS', '#EEF4FB'),
             ('FreeRADIUS: TLS (CA, CRL, CN = identidad) y LDAP', '#F9FAFB'),
             ('post-auth: ¿existe, no bloqueada y con grupo? → VLAN = rol×100', '#F9FAFB'),
             ('REST → identity: usuario y VLAN; AAA aprueba el puerto', '#F1F8F1'),
             ('identity crea la sesión y abre la ventana DHCP con la VLAN del rol', '#F1F8F1'),
             ('Kea entrega una IP de la subred del rol → reglas T1/T3/T5', '#E7F5EC')]
    ramas = [(2, 'falla TLS', 'Access-Reject uniforme\n(EAP-Failure) + radius.log', '#FBEAEA'),
             (3, 'no / bloqueada', 'Access-Reject uniforme\n+ g05-bloqueo cuenta el fallo', '#FBEAEA'),
             (6, 'IP fuera de rango', 'DHCP_FUERA_DE_RANGO\n(sin reglas)', '#FBEAEA')]
    story += [gi.diagrama_flujo(pasos, ramas, titulo='Flujo de autenticación y asignación de rol (R1)'),
              P('Figura 1. Flujo del módulo R1.', 'cap')]
    story += lista(['<b>Limitaciones:</b> un supplicant autenticado por puerto (app AAA); el VNRT puede descartar el '
                    'EAP-Failure hacia el cliente (el acceso real lo decide identity); un atacante puede bloquear una '
                    'cuenta ajena forzando 5 fallos (riesgo propio de cualquier bloqueo); el bloqueo de ppolicy de LDAP '
                    'no actúa con EAP-TLS, por eso existe g05-bloqueo.'])


def modulo_r2(story):
    story.append(P('2.2 Módulo 2 (R2): restricción de acceso a recursos privilegiados', 'h2'))
    story.append(P('<b>Objetivo.</b> Que cada rol llegue solo a los recursos que su política permite, que la decisión '
                   'se aplique con flujos en el switch de acceso y que cada intento quede registrado.', 'n'))
    story.append(tabla([
        ['Criterio del proyecto', 'Tipo', 'Cómo lo resuelve el módulo'],
        ['Escalabilidad frente a nodos y sesiones activas', 'Cuantitativo', '72 reglas fijas + 7 por usuario en su switch de acceso; la política se repite por switch.'],
        ['Tasa de nuevas sesiones', 'Cuantitativo', 'Reconciliación por diferencias contra ONOS; los cambios simultáneos se agrupan.'],
        ['Recursos críticos', 'Cuantitativo', 'Bloque crítico con descarte muestreado (meter de 10 pps) y firewall de Core-1.'],
        ['Clasificación de recursos y políticas por rol / multirol', 'Cualitativo', 'policy.yaml: general, intermedio y crítico; permite / deniega por rol.'],
        ['Permitir y denegar mediante flows; consistencia', 'Cualitativo', 'Compilador a 6 tablas OpenFlow; oráculo independiente (evaluate_access) para verificarlo.'],
        ['Logs y trazabilidad de accesos', 'Cualitativo', 'ACCESO_PERMITIDO e INTENTO_DENEGADO con usuario, rol, MAC y destino.'],
    ], [5 * cm, 2.4 * cm, 9.6 * cm]))
    story.append(P('Funciones', 'h3'))
    story.append(tabla([
        ['Función (archivo)', 'Responsabilidad'],
        ['r2ctl.evaluate_access(pol, rol, recurso[, proto, puerto])', 'Decisión PERMIT/DENY con motivo; deniega por defecto lo no registrado; DENY explícito prevalece.'],
        ['r2ctl.validate', 'Valida la política: prefijos sin solapes, críticos dentro del bloque crítico, grupos existentes.'],
        ['r2ctl.compile_all / tabla4 / tabla5_enrutada', 'Traduce la política y las sesiones a reglas OpenFlow (match, acción, prioridad).'],
        ['r2ctl.diff / reconcile', 'Compara con las reglas de ONOS e instala o retira solo la diferencia.'],
        ['r2ctl.ids_reglas', 'Genera desde la política las firmas de Suricata para registrar accesos permitidos y denegados.'],
        ['identity.on_acceso / on_intento', 'Registra el acceso con el usuario de la sesión 802.1X.'],
    ], [6.4 * cm, 10.6 * cm]))
    pasos = [('policy.yaml (roles, recursos, permite / deniega)', '#F9FAFB'),
             ('r2ctl.validate y compile_all → reglas de 6 tablas', '#EEF4FB'),
             ('identity: sesiones activas → reconcile (diferencia) por REST de ONOS', '#F1F8F1'),
             ('Paquete del usuario: T0 → T1 (puerto+MAC+IP) → T2 → T3 (VLAN del rol)', '#FFF7E6'),
             ('T4: deniega (29950) · total (29900) · permite (25000) · crítico (23000) · intranet · Internet', '#FFF7E6'),
             ('T5: hacia Core-1 con la VLAN del rol → recurso', '#E7F5EC')]
    ramas = [(3, 'IP/MAC ajena', 'Descarte + sensor\nde spoofing (R3)', '#FBEAEA'),
             (4, 'sin permiso', 'Descarte en T4 +\nINTENTO_DENEGADO (IDS)', '#FBEAEA'),
             (5, 'permitido', 'ACCESO_PERMITIDO\n(IDS, 1 por minuto)', '#F9FAFB')]
    story += [gi.diagrama_flujo(pasos, ramas, titulo='Flujo de autorización de acceso a recursos (R2)'),
              P('Figura 2. Flujo del módulo R2.', 'cap')]
    story += lista(['<b>Limitaciones:</b> la reconciliación compara todas las reglas en cada cambio (O(sesiones)); el '
                    'registro de accesos depende del espejo del IDS (puerto de usuarios de R-SW1) y se limita a un '
                    'evento por par usuario-destino por minuto; el ARP se valida por puerto y MAC (la REST de ONOS 2.7 '
                    'no expone ARP_SPA).'])
    story.append(P('2.3 Módulo 3 (R3): resumen del requerimiento específico', 'h2'))
    story.append(P('Suricata sobre el espejo GRE del puerto de usuarios detecta escaneos, spoofing externo, requests '
                   'maliciosos y ráfagas; un sensor en el switch detecta el spoofing interno. identity bloquea la MAC '
                   'autenticada del atacante con una regla T2 (prioridad 40000, 300 s), pasa a cuarentena a la 3.ª '
                   'alerta en 10 min y registra cada incidente. El diseño completo está en el informe de la experiencia '
                   '(EXP_TEL354_LAB7_G5).', 'n'))
    story.append(P('2.4 APIs expuestas', 'h2'))
    story.append(tabla([
        ['API', 'Método y ruta', 'Uso'],
        ['identity', 'POST /identity/sessions', 'FreeRADIUS entrega usuario y VLAN (R1)'],
        ['identity', 'POST /identity/aaa · POST /identity/dhcp', 'Eventos AAA y concesiones de Kea (R1)'],
        ['identity', 'POST /identity/cuenta', 'Fallos, bloqueos y desbloqueos de cuenta (R1-03)'],
        ['identity', 'GET /identity/sessions · /accesos · /intentos', 'Sesiones y registro de accesos (R1, R2)'],
        ['identity', 'POST /identity/alert · POST|DELETE /identity/block/&lt;mac&gt;', 'Alertas del IDS y bloqueo (R3)'],
        ['identity', 'GET /identity/incidents?desde=', 'Registro de seguridad (R1, R2, R3, R4)'],
        ['r2ctl (CLI)', 'validate · plan · apply · verify · ids-reglas', 'Validar, aplicar y verificar la política; generar firmas'],
        ['ONOS (consumida)', 'REST /onos/v1/flows, /meters, /devices; /onos/aaa', 'Programación de reglas y meters; estado de AAA'],
    ], [2.6 * cm, 7.6 * cm, 6.8 * cm]))
    story.append(PageBreak())


# ============================================================ 3. Hipótesis
def hipotesis(story):
    story.append(P('3. Hipótesis de comportamiento y condiciones de falla', 'h1'))
    story.append(P('Para cada módulo se plantea cómo debería responder en condiciones normales, ante errores y ante '
                   'fallas simultáneas, y cómo se valida.', 'n'))
    story.append(tabla([
        ['Escenario', 'Hipótesis (comportamiento esperado)', 'Validación', 'Resultado'],
        ['Certificado inválido, usuario inexistente o inyección en la identidad', 'Mismo rechazo para todos; nadie puede saber si una cuenta existe', '1.1.2 (eapol_test)', 'Falló al inicio (enumeración); corregido → PASS'],
        ['5 fallos seguidos de una cuenta en 15 min', 'Bloqueo de 15 min, incluso con el certificado correcto', '1.2.1 (slice y unitaria)', 'PASS'],
        ['Rol o recurso fuera del inventario', 'Denegación por defecto, sin excepciones', '2.1.3', 'Fallaba con KeyError; corregido → PASS'],
        ['PERMIT y DENY sobre el mismo tráfico', 'Prevalece DENY por prioridad en T4', '2.2.1', 'PASS'],
        ['IP o MAC falsificada en el puerto', 'Descarte en T1; 3 paquetes en 10 s → bloqueo', '3.1.5 + slice (hping3 -c 3)', 'No detectaba con 3 paquetes; corregido → PASS'],
        ['Caída de ONOS-1 + Atomix-1 (DF1)', 'ONOS-2 asume los 6 switches; quórum 2/3', 'prueba-caida-df1.sh', '6/6 en ~11 s'],
        ['Caída de cada enlace entre switches, o de Core-1', 'Ningún switch pierde el control (BFD + Fast Failover)', 'test_redundancia (25) + prueba-fallas.sh', 'Encontró un fallo de R-SW2 → corregido y probado en el slice'],
        ['Reinicio de identity con sesiones activas', 'Las reglas siguen en los switches; al volver, reinstala desde sessions.json', 'Reinicios en cada despliegue', 'Observado sin cortes (no medido formalmente)'],
        ['IDS caído o saturado', 'R3 pierde las firmas; siguen el anti-spoofing, el sensor del switch y R2', 'carga-ids.sh (400 sesiones/s)', 'Sin pérdidas hasta 400 sesiones/s'],
        ['Ataque y logins legítimos a la vez', 'Solo se bloquea la MAC atacante; el vecino del mismo puerto sigue', '3.2.1 + testigo en prueba-r3', 'PASS; testigo nunca afectado'],
        ['Flood de varios cientos de Mbit/s', 'Riesgo: el espejo GRE comparte la red de gestión con el clúster', 'Ataques acotados a ~100 Mbit/s', 'Limitación documentada'],
    ], [4 * cm, 5.4 * cm, 3.6 * cm, 4 * cm]))
    story.append(PageBreak())


# ============================================================ 4. Validación
def validacion(story):
    story.append(P('4. Diseño y estructuración de la estrategia de validación', 'h1'))
    story.append(tabla([
        ['Tipo de prueba', 'Alcance', 'Implementación en el repositorio'],
        ['Unitarias', 'Funciones aisladas, sin red', 'pruebas/unitarias: test_r2ctl, test_identity, test_ddos, test_redundancia, test_lab7 (114 pruebas)'],
        ['Unitarias del módulo real', 'FreeRADIUS y Suricata aislados', 'test_lab7_slice: eapol_test contra FreeRADIUS y suricata -r sobre capturas sintéticas (11 pruebas)'],
        ['Integración', 'Comunicación entre módulos', 'verify --roles all (802.1X real → identity → ONOS → OVS), prueba-r2-trazabilidad (IDS → identity)'],
        ['Funcionales', 'Requerimientos de punta a punta', 'prueba-r1.sh, prueba-r3.sh, prueba-r4.sh, prueba-fallas.sh, prueba-caida-df1.sh'],
        ['Rendimiento', 'Carga y concurrencia', 'prueba-r1.sh latencia y carga, prueba-r2-escala.sh, carga-ids.sh'],
    ], [3.2 * cm, 3.8 * cm, 10 * cm]))
    story.append(P('4.1 Pruebas obligatorias: mapeo a las funciones reales', 'h2'))
    story.append(P('Las funciones del informe previo son referenciales; cada código se mapea a la función real y se '
                   'documenta con la nomenclatura X.Y.Z (X = módulo, Y = funcionalidad, Z = prueba).', 'n'))
    story.append(tabla([
        ['Código', 'Función referencial', 'Función real', 'Datos válidos / inválidos', 'Tipo'],
        ['R1-01', 'validate_credentials', 'FreeRADIUS EAP-TLS + identity.on_approved', 'Certificado propio de alu01/doc01/adm01/admin01', 'Normal'],
        ['R1-02', 'validate_credentials', 'FreeRADIUS + g05-bloqueo.USUARIO_OK', "Certificado ajeno, CA falsa, caducado, revocado, vacío, ' OR '1'='1, *, )(uid=*", 'Inválido'],
        ['R1-03', 'register_failed_attempt / is_locked', 'g05-bloqueo (mismos nombres)', '4 fallos (N−1) y 5 fallos (N)', 'Límite'],
        ['R2-01', 'evaluate_access', 'r2ctl.evaluate_access', 'Admin y docente sobre G04 (crítico)', 'Normal / inválido'],
        ['R2-02', 'evaluate_access', 'r2ctl.evaluate_access / allowed', "'Invitado', 99, None; 'consola_inexistente'", 'Límite'],
        ['R2-03', 'translate_policy', 'r2ctl.compile_all (T4)', 'permite G07 y deniega G07 en el mismo rol', 'Normal'],
        ['R3-01', 'detect_port_scan', 'Firma 1000001 (Suricata)', '10 y 11 SYN a puertos no ofrecidos; 15 a puertos ofrecidos', 'Límite / falso positivo'],
        ['R3-02', 'detect_network_scan', 'Firmas 1000002 / 1000003', '15 y 16 hosts por ICMP; 11 por TCP', 'Normal'],
        ['R3-03', 'check_ip_binding', 'Reglas T1 + identity.watch_spoofing', 'IP registrada y IP ajena por el mismo puerto y MAC', 'Normal / inválido'],
        ['R3-04', 'detect_malicious_requests', 'Firma 1000020', '40 y 41 GET; dos clientes', 'Normal'],
        ['R3-05', 'build_block_rule', 'compile_all (T2) + identity.vencer', 'Atacante bloqueado y vecino legítimo; 299 y 301 s', 'Normal'],
        ['R3-06', 'log_incident', 'identity.log (incidentes.jsonl)', 'Alerta de escaneo de puertos', 'Normal'],
    ], [1.3 * cm, 3.1 * cm, 4.2 * cm, 6.2 * cm, 2.2 * cm]))
    story.append(P('4.2 Esquema de cobertura de código', 'h2'))
    story.append(P('Medida con pytest-cov sobre la corrida completa (125 pruebas). La cobertura de las funciones que '
                   'toman decisiones es la que miden las pruebas unitarias; el resto de cada archivo es E/S (REST de '
                   'ONOS, SSH, CLI, bucles de servicio) y se ejercita en las pruebas funcionales del slice.', 'n'))
    filas = [['Archivo', 'Función', 'Cubiertas / sentencias', '%']]
    total = None
    for l in gi.leer('cobertura-funciones.txt').splitlines():
        m = re.match(r'(\S+)\s+(\S+)\s+(\d+)/(\d+)\s+([\d.]+) %', l)
        if m:
            filas.append([m.group(1), m.group(2), f'{m.group(3)}/{m.group(4)}', m.group(5)])
        elif l.startswith('TOTAL'):
            total = l
    story.append(tabla(filas, [4 * cm, 6 * cm, 4 * cm, 3 * cm]))
    if total:
        m = re.search(r'(\d+)/(\d+)\s+([\d.]+) %', total)
        story.append(P(f'<b>Total de la lógica de decisión: {m.group(1)}/{m.group(2)} sentencias ({m.group(3)} %).</b> '
                       'Bajo el 70 %: key y group_spec (formato para ONOS y OVS, se ejercitan al desplegar), '
                       'procesar (sus ramas de fallo y bloqueo se prueban contra el servicio real en 1.2.1), validate '
                       '(ramas de error de una política mal escrita), recurso_de_ip (IP mal formada) y vencer '
                       '(vencimiento de sesiones y cuarentenas; el de bloqueos sí está cubierto).', 'n'))
    filas = [['Archivo', 'Sentencias', 'Sin cubrir', 'Cobertura']]
    for l in gi.leer('cobertura.txt').splitlines():
        m = re.match(r'(politica/\S+|infraestructura/files/\S+)\s+(\d+)\s+(\d+)\s+(\d+%)', l)
        if m and m.group(4) != '0%':
            filas.append([m.group(1), m.group(2), m.group(3), m.group(4)])
    story.append(P('Cobertura por archivo (los scripts de despliegue sin pruebas unitarias se omiten):', 'n'))
    story.append(tabla(filas, [8 * cm, 3 * cm, 3 * cm, 3 * cm]))
    story.append(PageBreak())


def fichas(story):
    story.append(P('4.3 Casos de prueba (X.Y.Z)', 'h2'))
    story.append(P('Cada caso incluye los campos del formato: número, tipo, objetivos, prerrequisitos, procedimiento, '
                   'resultados esperados, resultado obtenido (PASS / FAIL / NT, tomado de la ejecución de pytest -v: '
                   f'<b>{gi.resumen_pytest()}</b>), evidencias y comentarios.', 'n'))
    for f in gi.FICHAS:
        story.append(gi.ficha(f))
    story.append(P('4.4 Ejemplo funcional de ejecución', 'h2'))
    story.append(codigo('$ python3 -m pytest pruebas/unitarias/test_lab7.py pruebas/unitarias/test_lab7_slice.py -v\n' +
                        '\n'.join(re.sub(r'^pruebas/unitarias/', '', l) for l in gi.leer('pytest.txt').splitlines()
                                  if 'test_lab7' in l)[:6000]))
    story.append(PageBreak())


# ============================================================ 5. Avance
def avance(story):
    story.append(P('5. Avance del proyecto: implementación y reporte de pruebas', 'h1'))
    story.append(tabla([
        ['Requerimiento', 'Estado', 'Evidencia principal'],
        ['R1 · 802.1X, roles y multirol', 'Implementado y probado', '21/21 accesos inválidos bloqueados; EAP-TLS en 82 ms; ~33 auth/s; bloqueo al 5.º fallo; multi01 → admin'],
        ['R2 · recursos por rol', 'Implementado y probado', '216 pruebas, 0 discrepancias, 142/142 bloqueados; 53/53 intentos registrados con usuario; 200 sesiones con 1 503 reglas'],
        ['R3 · ataques encubiertos', 'Implementado y probado', '8/8 ataques mitigados en 0,3–4,5 s; 0 falsos positivos; IDS sin pérdidas a 400 sesiones/s'],
        ['R4 · DDoS (adicional)', 'Implementado y probado', 'Fuentes identificadas en ~14 s; víctima de 75–125 a 2–6 Mbit/s; testigo sin limitar'],
        ['Alta disponibilidad', 'Implementado y probado', 'Clúster ONOS + Atomix; caída de DF1 → ONOS-2 en ~11 s; enlaces y Core-1 sin cortes'],
    ], [4.2 * cm, 3.4 * cm, 9.4 * cm]))
    story.append(P('Defectos encontrados por las pruebas y corregidos', 'h2'))
    story.append(tabla([
        ['Prueba que lo encontró', 'Defecto', 'Corrección'],
        ['1.1.2 (R1-02)', 'Un usuario inexistente recibía un rechazo distinto al de un certificado inválido: se podía enumerar cuentas.', 'Existencia y bloqueo en post-auth; EAP-Failure en todo rechazo.'],
        ['2.1.3 (R2-02)', 'Un rol desconocido lanzaba KeyError en la decisión de acceso.', 'evaluate_access deniega por defecto lo no registrado.'],
        ['3.1.5 (R3-03) en el slice', 'Con hping3 -c 3 el sensor de spoofing no detectaba (ONOS repartía los paquetes en dos lecturas).', 'Ventana de 10 s.'],
        ['test_redundancia', 'Con el enlace Core-1↔Core-2 caído, Core-2 perdía el camino hacia ONOS-2.', 'R-SW2 entrega a Core-2 por su enlace directo (grupo 50002).'],
        ['prueba-r3.sh', 'El IDS veía las peticiones HTTP 70 s tarde porque el servidor no las confirmaba.', 'El servidor de prueba responde HTTP real.'],
    ], [3.4 * cm, 7.4 * cm, 6.2 * cm]))
    story.append(P('6. Conclusiones', 'h1'))
    story += lista([
        '<b>Probar el módulo real, no una copia:</b> las pruebas de R1 y R3 corren contra el FreeRADIUS y el Suricata del '
        'slice en el límite exacto del umbral; así aparecieron defectos que una implementación simulada no habría mostrado.',
        '<b>Un oráculo independiente vale más que muchas pruebas sueltas:</b> evaluate_access decide desde la política y un '
        'simulador recorre las reglas compiladas; coinciden en las 216 combinaciones, y una mutación manual se detecta.',
        '<b>Los límites del módulo vienen de la plataforma:</b> el sondeo de ONOS (5 s), el supplicant único por puerto y '
        'el espejo por la red de gestión fijan tiempos y alcance; están medidos y documentados.',
        '<b>Contingencias sin punto único de falla:</b> el clúster, BFD + Fast Failover y su simulador automatizado cubren '
        'cada enlace, Core-1 y el dominio DF1.',
        '<b>Siguiente paso:</b> reconciliación incremental por sesión, sondeo de ONOS a 2 s para R3/R4 y una red propia '
        'para el espejo del IDS.',
    ])
    story.append(P(f'Repositorio: <link href="{gi.REPO}"><font color="#1F3A5F"><b>{gi.REPO}</b></font></link>', 'n'))


def main():
    story = []
    portada(story)
    tecnologias(story)
    despliegue(story)
    modulo_r1(story)
    modulo_r2(story)
    hipotesis(story)
    validacion(story)
    fichas(story)
    avance(story)

    def pie(c, doc):
        c.saveState()
        c.setFont('Arial', 7.5)
        c.setFillColor(gi.colors.HexColor('#6B7280'))
        c.drawString(2 * cm, 1.2 * cm, 'TEL354 · Informe Previo Lab 7 · Grupo 5')
        c.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f'Página {doc.page}')
        c.restoreState()
    doc = SimpleDocTemplate(str(SALIDA), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm,
                            bottomMargin=1.8 * cm, title='Informe Previo Lab 7 · G05', author='Grupo 5 · TEL354')
    doc.build(story, onFirstPage=lambda c, d: None, onLaterPages=pie)
    print(SALIDA, 'generado;', gi.resumen_pytest())


if __name__ == '__main__':
    main()
