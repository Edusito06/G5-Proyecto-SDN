"""Detector de DDoS por consumo de ancho de banda (R4, G05). Sin E/S: identity le pasa
los contadores de ONOS y ejecuta las acciones que devuelve (así se prueba en unitarias).

Entradas por muestra (contadores acumulados y el instante en que ONOS los leyó):
  usuarios: {mac: (bytes, paquetes, t)}   regla T3 de cada usuario (todo lo que envía)
  entrada:  {mac: (bytes, paquetes, t)}   reglas T5 de entrega a cada usuario (lo que recibe)
  ofrecido: {mac: (bytes, paquetes, t)}   regla T2 de límite de R4 (antes del meter)
  recursos: {g:   (bytes, paquetes, t)}   reglas T4 que permiten llegar a cada recurso

Decisiones (una fuente, además, debe ENVIAR más de ASIMETRIA veces lo que RECIBE: quien
descarga a 1 Gbit/s manda ~30 Mbit/s de ACK, pero recibe 40 veces más; el atacante
manda y casi no recibe):
  - Fuente volumétrica: un usuario supera USER_BPS o USER_PPS durante SOSTENER muestras.
  - Ataque distribuido: un recurso recibe más de SRV_BPS (o SRV_PPS) durante SOSTENER
    muestras; son fuentes los usuarios que en ese momento aportan más de SHARE_BPS (o
    SHARE_PPS), aunque ninguno supere el umbral individual.
  - Levantar: la tasa ofrecida de una fuente limitada queda bajo la mitad de su umbral
    durante ENFRIAR segundos.
"""
import os


def _f(nombre, defecto):
    return float(os.getenv(nombre, defecto))


class Detector:
    def __init__(self, **cfg):
        g = lambda k, env, d: float(cfg.get(k, _f(env, d)))
        self.user_bps = g('user_bps', 'DDOS_USER_BPS', 50e6)
        self.user_pps = g('user_pps', 'DDOS_USER_PPS', 15000)
        self.srv_bps = g('srv_bps', 'DDOS_SRV_BPS', 80e6)
        self.srv_pps = g('srv_pps', 'DDOS_SRV_PPS', 20000)
        self.share_bps = g('share_bps', 'DDOS_SHARE_BPS', 10e6)
        self.share_pps = g('share_pps', 'DDOS_SHARE_PPS', 2000)
        self.sostener = int(g('sostener', 'DDOS_SOSTENER', 2))
        self.enfriar = g('enfriar', 'DDOS_ENFRIAR', 30)
        self.asimetria = g('asimetria', 'DDOS_ASIMETRIA', 1.0)
        self.prev = {}          # (clase, clave) -> (bytes, paquetes, t)
        self.tasa = {}          # (clase, clave) -> (bps, pps)
        self.racha = {}         # (clase, clave) -> muestras seguidas sobre el umbral
        self.bajo_desde = {}    # mac limitada -> t desde que su oferta está baja

    def _tasas(self, clase, contadores):
        for k, (b, p, t) in contadores.items():
            ant = self.prev.get((clase, k))
            self.prev[(clase, k)] = (b, p, t)
            if ant and t > ant[2] and b >= ant[0]:          # ONOS actualizó la muestra
                dt = t - ant[2]
                self.tasa[(clase, k)] = ((b - ant[0]) * 8 / dt, (p - ant[1]) / dt)
            elif ant and b < ant[0]:                       # regla reinstalada: reinicia
                self.tasa.pop((clase, k), None)

    def _sostenido(self, clave, alto, nuevo):
        if not nuevo:
            return self.racha.get(clave, 0) >= self.sostener
        self.racha[clave] = self.racha.get(clave, 0) + 1 if alto else 0
        return self.racha[clave] >= self.sostener

    def _emisor(self, mac, bps):
        """¿Envía bastante más de lo que recibe? (sin dato de entrada: sí)."""
        rx = self.tasa.get(('i', mac), (0, 0))[0]
        return bps > self.asimetria * rx

    def actualizar(self, usuarios, recursos, ofrecido, limitados, ahora, entrada=None):
        """Devuelve [(accion, mac, detalle)] con accion 'limitar' o 'levantar'."""
        nuevos = {('u', k) for k, v in usuarios.items() if self.prev.get(('u', k), (0, 0, -1))[2] != v[2]}
        nuevos |= {('r', k) for k, v in recursos.items() if self.prev.get(('r', k), (0, 0, -1))[2] != v[2]}
        self._tasas('u', usuarios)
        self._tasas('r', recursos)
        self._tasas('o', ofrecido)
        self._tasas('i', entrada or {})
        acciones, ya = [], set(limitados)

        for mac in usuarios:
            bps, pps = self.tasa.get(('u', mac), (0, 0))
            alto = (bps > self.user_bps or pps > self.user_pps) and self._emisor(mac, bps)
            if self._sostenido(('u', mac), alto, ('u', mac) in nuevos) and mac not in ya:
                acciones.append(('limitar', mac, {'motivo': 'volumétrico', 'bps': int(bps), 'pps': int(pps)}))
                ya.add(mac)

        for g in recursos:
            bps, pps = self.tasa.get(('r', g), (0, 0))
            alto = bps > self.srv_bps or pps > self.srv_pps
            if self._sostenido(('r', g), alto, ('r', g) in nuevos):
                for mac in usuarios:
                    ubps, upps = self.tasa.get(('u', mac), (0, 0))
                    if mac not in ya and (ubps > self.share_bps or upps > self.share_pps) \
                            and self._emisor(mac, ubps):
                        acciones.append(('limitar', mac, {'motivo': f'distribuido contra {g}',
                                                          'bps': int(ubps), 'pps': int(upps),
                                                          'recurso': g, 'recurso_bps': int(bps)}))
                        ya.add(mac)

        for mac in limitados:
            bps, pps = self.tasa.get(('o', mac), (None, None))
            if bps is None:
                continue
            bajo = bps < self.share_bps / 2 and pps < self.share_pps / 2
            if not bajo:
                self.bajo_desde.pop(mac, None)
                continue
            desde = self.bajo_desde.setdefault(mac, ahora)
            if ahora - desde >= self.enfriar:
                acciones.append(('levantar', mac, {'ofrecido_bps': int(bps)}))
                self.bajo_desde.pop(mac, None)
                self.racha.pop(('u', mac), None)
        return acciones

    def resumen(self):
        """Tasas actuales (para GET /identity/trafico)."""
        out = {'usuarios': {}, 'recursos': {}, 'ofrecido': {}, 'entrada': {}}
        nombres = {'u': 'usuarios', 'r': 'recursos', 'o': 'ofrecido', 'i': 'entrada'}
        for (clase, k), (bps, pps) in self.tasa.items():
            out[nombres[clase]][k] = {'bps': int(bps), 'pps': int(pps)}
        return out
