//go:build linux

package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/aurva-io/ai-traffic-interceptor/internal/bpf/dns"
	"github.com/aurva-io/ai-traffic-interceptor/internal/bpf/generated"
	"github.com/aurva-io/ai-traffic-interceptor/internal/config"
)

// Manager holds loaded BPF objects and the attach links for cleanup.
type Manager struct {
	Objs   *generated.AIInterceptorObjects
	log    *zap.Logger
	dnsSvc *dns.Service
	links  []io.Closer
}

func NewManager(cfg *config.Config, log *zap.Logger) (*Manager, error) {
	objs := &generated.AIInterceptorObjects{}

	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelBranch,
		},
	}

	if err := generated.LoadAIInterceptorObjects(objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("BPF verifier rejected program: %v", ve)
		}

		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	m := &Manager{
		Objs: objs,
		log:  log,
		dnsSvc: &dns.Service{
			AIDestMap: objs.AiDestinations,
			AIDomains: cfg.AIDomains,
			Log:       log,
		},
	}

	if err := m.writeProxyConfig(cfg.ProxyIP, cfg.ProxyPort); err != nil {
		objs.Close()
		return nil, err
	}

	iface, err := net.InterfaceByName(cfg.NetworkInterface)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("interface %q: %w", cfg.NetworkInterface, err)
	}

	if err := m.attachTC(iface); err != nil {
		objs.Close()
		return nil, err
	}

	if err := m.attachCgroup(cfg.CgroupPath); err != nil {
		m.closeLinks()
		objs.Close()
		return nil, err
	}

	return m, nil
}

func (m *Manager) Close() error {
	m.closeLinks()
	return m.Objs.Close()
}

func (m *Manager) closeLinks() {
	for _, l := range m.links {
		l.Close()
	}

	m.links = nil
}

// writeProxyConfig writes the proxy IP+port into the proxy_config BPF map.
func (m *Manager) writeProxyConfig(proxyIP string, proxyPort uint16) error {
	ip := net.ParseIP(proxyIP).To4()
	if ip == nil {
		return fmt.Errorf("invalid proxy IP %q", proxyIP)
	}

	cfg := generated.AIInterceptorProxyConfigT{
		Ip:   binary.NativeEndian.Uint32(ip),
		Port: ntohs(proxyPort),
	}

	return m.Objs.ProxyConfig.Update(proxyConfigKey, cfg, ebpf.UpdateAny)
}

// attachTC adds a clsact qdisc and an ingress BPF filter to iface.
func (m *Manager) attachTC(iface *net.Interface) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Index,
			Handle:    netlink.MakeHandle(tcClsactMajor, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    netlink.MakeHandle(tcClsactMajor, tcIngressMinor),
			Handle:    netlink.MakeHandle(0, tcFilterHandle),
			Protocol:  unix.ETH_P_ALL,
			Priority:  tcFilterPriority,
		},
		Fd:           m.Objs.TcDnsObserver.FD(),
		Name:         "tc_dns_observer",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("add TC filter: %w", err)
	}

	m.links = append(m.links, &tcAttachment{iface: iface, filter: filter})

	return nil
}

type tcAttachment struct {
	iface  *net.Interface
	filter *netlink.BpfFilter
}

func (t *tcAttachment) Close() error {
	return netlink.FilterDel(t.filter)
}

// attachCgroup attaches the cgroup/connect4 program to the root cgroup.
func (m *Manager) attachCgroup(cgroupPath string) error {
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: m.Objs.CgroupConnect4,
		Attach:  ebpf.AttachCGroupInet4Connect,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup/connect4: %w", err)
	}

	m.links = append(m.links, l)

	return nil
}
