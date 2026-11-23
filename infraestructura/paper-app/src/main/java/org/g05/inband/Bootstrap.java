package org.g05.inband;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IPv4;
import org.onlab.packet.TpPort;
import org.onlab.packet.VlanId;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Link;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(immediate = true, property = {"rootPort=", "ports=", "attachments="})
public class Bootstrap {
    private static final Logger LOG = LoggerFactory.getLogger(Bootstrap.class);
    private static final DeviceId ROOT = DeviceId.deviceId("of:0000000000000005");
    private static final Ip4Address ONOS = Ip4Address.valueOf("10.100.0.2");
    private static final int PRIORITY = 62500;
    private static final TpPort OPENFLOW = TpPort.tpPort(6653);
    @Reference protected CoreService core;
    @Reference protected ComponentConfigService config;
    @Reference protected PacketService packets;
    @Reference protected FlowRuleService flows;
    @Reference protected LinkService links;
    @Reference protected DeviceService devices;

    private final Set<ConnectPoint> trusted = new HashSet<>();
    /** OpenFlow port on DC-DIST connected directly to the controller. */
    private String rootPort;
    /** Trusted infrastructure connect points, separated by commas. */
    private String ports;
    /** Authorized IPv4 to ingress connect point mappings, separated by commas. */
    private String attachments;
    private final Map<Ip4Address, ConnectPoint> entryByIp = new HashMap<>();
    private final PacketProcessor processor = this::onPacket;
    private ApplicationId app;
    private ConnectPoint controllerPort;

    @Activate
    protected synchronized void activate(ComponentContext ctx) {
        app = core.registerApplication("org.g05.inband");
        config.registerProperties(getClass());
        packets.addProcessor(processor, PacketProcessor.director(1));
        modified(ctx);
    }

    @Modified
    protected synchronized void modified(ComponentContext ctx) {
        Dictionary<String, Object> values = ctx.getProperties();
        rootPort = String.valueOf(values.get("rootPort"));
        ports = String.valueOf(values.get("ports"));
        attachments = String.valueOf(values.get("attachments"));
        if (rootPort.isEmpty() || ports.isEmpty() || attachments.isEmpty()) {
            clear();
            return;
        }
        Set<ConnectPoint> newPorts = new HashSet<>();
        Map<Ip4Address, ConnectPoint> newEdges = new HashMap<>();
        ConnectPoint root;
        try {
            root = new ConnectPoint(ROOT, PortNumber.portNumber(Long.parseLong(rootPort.trim())));
            for (String port : ports.split(",")) {
                newPorts.add(ConnectPoint.deviceConnectPoint(port.trim()));
            }
            for (String edge : attachments.split(",")) {
                String[] fields = edge.trim().split("=", -1);
                if (fields.length != 2) {
                    throw new IllegalArgumentException(edge);
                }
                Ip4Address ip = Ip4Address.valueOf(fields[0]);
                ConnectPoint entry = ConnectPoint.deviceConnectPoint(fields[1]);
                if (!newPorts.contains(entry) || entry.equals(root) || newEdges.containsValue(entry)
                        || newEdges.put(ip, entry) != null) {
                    throw new IllegalArgumentException(edge);
                }
            }
            if (!newPorts.contains(root)) {
                throw new IllegalArgumentException("El puerto de ONOS debe estar en ports");
            }
        } catch (IllegalArgumentException error) {
            LOG.error("Configuración de bootstrap inválida", error);
            return;
        }
        if (root.equals(controllerPort) && newPorts.equals(trusted) && newEdges.equals(entryByIp)) {
            return;
        }
        clear();
        controllerPort = root;
        trusted.addAll(newPorts);
        entryByIp.putAll(newEdges);
        entryByIp.forEach((ip, cp) -> packets.requestPackets(probe(cp, ip), PacketPriority.CONTROL,
                app, Optional.of(cp.deviceId())));
        LOG.info("Bootstrap preparado con {} puntos de incorporación", entryByIp.size());
    }

    private TrafficSelector probe(ConnectPoint cp, Ip4Address ip) {
        return DefaultTrafficSelector.builder().matchInPort(cp.port()).matchVlanId(VlanId.NONE)
                .matchEthType(Ethernet.TYPE_ARP).matchArpOp(ARP.OP_REQUEST)
                .matchArpSpa(ip).matchArpTpa(ONOS).build();
    }

    private synchronized void onPacket(PacketContext ctx) {
        Ethernet frame = ctx.inPacket().parsed();
        if (ctx.isHandled() || frame == null || frame.getEtherType() != Ethernet.TYPE_ARP
                || frame.getVlanID() != Ethernet.VLAN_UNTAGGED || !(frame.getPayload() instanceof ARP)) {
            return;
        }
        ARP arp = (ARP) frame.getPayload();
        if (arp.getOpCode() != ARP.OP_REQUEST || !ONOS.equals(Ip4Address.valueOf(arp.getTargetProtocolAddress()))) {
            return;
        }
        Ip4Address ip = Ip4Address.valueOf(arp.getSenderProtocolAddress());
        ConnectPoint from = ctx.inPacket().receivedFrom();
        if (!from.equals(entryByIp.get(ip))) {
            return;
        }
        ctx.block();
        Optional<List<Link>> path = pathFrom(from.deviceId());
        if (!path.isPresent()) {
            return; // El siguiente ARP se reintenta una vez que LLDP descubre el camino.
        }
        List<FlowRule> rules = new ArrayList<>();
        ConnectPoint ingress = from;
        for (Link link : path.get()) {
            addPair(rules, ingress, link.src(), ip);
            ingress = link.dst();
        }
        addPair(rules, ingress, controllerPort, ip);
        flows.applyFlowRules(rules.toArray(new FlowRule[0]));
        LOG.info("ARP {} desde {}: {} reglas de control pedidas a ONOS", ip, from, rules.size());
        // Las reglas son asíncronas. El próximo ARP viaja por el camino ya instalado.
    }

    private Optional<List<Link>> pathFrom(DeviceId start) {
        if (!devices.isAvailable(start) || !devices.isAvailable(ROOT)) {
            return Optional.empty();
        }
        ArrayDeque<DeviceId> pending = new ArrayDeque<>();
        Set<DeviceId> seen = new HashSet<>();
        Map<DeviceId, Link> previous = new HashMap<>();
        pending.add(start);
        seen.add(start);
        while (!pending.isEmpty()) {
            DeviceId current = pending.remove();
            if (current.equals(ROOT)) {
                List<Link> path = new ArrayList<>();
                while (!current.equals(start)) {
                    Link link = previous.get(current);
                    path.add(link);
                    current = link.src().deviceId();
                }
                Collections.reverse(path);
                return Optional.of(path);
            }
            for (Link link : links.getDeviceEgressLinks(current)) {
                DeviceId next = link.dst().deviceId();
                Link reverse = links.getLink(link.dst(), link.src());
                if (link.state() == Link.State.ACTIVE && reverse != null && reverse.state() == Link.State.ACTIVE
                        && trusted.contains(link.src()) && trusted.contains(link.dst())
                        && devices.isAvailable(next) && seen.add(next)) {
                    previous.put(next, link);
                    pending.add(next);
                }
            }
        }
        return Optional.empty();
    }

    private void addPair(List<FlowRule> rules, ConnectPoint in, ConnectPoint out, Ip4Address ip) {
        addDirection(rules, in, out, ip, ONOS, true);
        addDirection(rules, out, in, ONOS, ip, false);
    }

    private void addDirection(List<FlowRule> rules, ConnectPoint in, ConnectPoint out,
                              Ip4Address src, Ip4Address dst, boolean toController) {
        TrafficSelector arp = DefaultTrafficSelector.builder().matchInPort(in.port()).matchVlanId(VlanId.NONE)
                .matchEthType(Ethernet.TYPE_ARP).matchArpSpa(src).matchArpTpa(dst).build();
        TrafficSelector.Builder tcp = DefaultTrafficSelector.builder().matchInPort(in.port()).matchVlanId(VlanId.NONE)
                .matchEthType(Ethernet.TYPE_IPV4).matchIPSrc(src.toIpPrefix()).matchIPDst(dst.toIpPrefix())
                .matchIPProtocol(IPv4.PROTOCOL_TCP);
        if (toController) {
            tcp.matchTcpDst(OPENFLOW);
        } else {
            tcp.matchTcpSrc(OPENFLOW);
        }
        for (TrafficSelector selector : new TrafficSelector[]{arp, tcp.build()}) {
            rules.add(DefaultFlowRule.builder().forDevice(in.deviceId()).forTable(0)
                    .withPriority(PRIORITY).withSelector(selector)
                    .withTreatment(DefaultTrafficTreatment.builder().setOutput(out.port()).build())
                    .fromApp(app).makePermanent().build());
        }
    }

    private void clear() {
        entryByIp.forEach((ip, cp) -> packets.cancelPackets(probe(cp, ip), PacketPriority.CONTROL,
                app, Optional.of(cp.deviceId())));
        entryByIp.clear();
        trusted.clear();
        controllerPort = null;
        flows.removeFlowRulesById(app);
    }

    @Deactivate
    protected synchronized void deactivate() {
        packets.removeProcessor(processor);
        clear();
        config.unregisterProperties(getClass(), false);
    }
}
