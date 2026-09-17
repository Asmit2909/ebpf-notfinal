package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"bpf-lsm-sec/pkg/bpf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

type BinaryPolicy struct {
	Path            string   `yaml:"path"`
	Ancestors       []string `yaml:"ancestors,omitempty"`
	Args            []string `yaml:"args,omitempty"`
	OnlyInContainer bool     `yaml:"only_in_container,omitempty"`
}

type NetworkPolicy struct {
	Port      uint16 `yaml:"port,omitempty"`
	PortRange string `yaml:"port_range,omitempty"`
	IP        string `yaml:"ip,omitempty"`
	CIDR      string `yaml:"cidr,omitempty"`
	// Direction scopes the rule to specific network hooks. Accepts a single
	// value or a comma-separated list: connect, bind, listen, accept,
	// ingress (= bind,listen,accept), egress (= connect), any.
	// Omitted or "any" means the rule applies to every network hook.
	Direction string `yaml:"direction,omitempty"`
}

// Direction bitmask flags. Must stay in sync with the DIR_* defines in
// pkg/bpf/lsm_enforce.bpf.c.
const (
	DirAny     uint32 = 0
	DirConnect uint32 = 1 << 0
	DirBind    uint32 = 1 << 1
	DirListen  uint32 = 1 << 2
	DirAccept  uint32 = 1 << 3

	DirIngress = DirBind | DirListen | DirAccept
	DirEgress  = DirConnect
)

var directionNames = map[string]uint32{
	"any":     DirAny,
	"connect": DirConnect,
	"bind":    DirBind,
	"listen":  DirListen,
	"accept":  DirAccept,
	"ingress": DirIngress,
	"egress":  DirEgress,
}

// parseDirection turns a policy `direction:` string into a bitmask.
// An empty string yields DirAny (apply everywhere), preserving the behaviour
// of policies written before this field existed.
// dirLabel renders a direction mask for human-readable logging.
func dirLabel(mask uint32) string {
	if mask == DirAny {
		return "any"
	}
	var parts []string
	if mask&DirConnect != 0 {
		parts = append(parts, "connect")
	}
	if mask&DirBind != 0 {
		parts = append(parts, "bind")
	}
	if mask&DirListen != 0 {
		parts = append(parts, "listen")
	}
	if mask&DirAccept != 0 {
		parts = append(parts, "accept")
	}
	return strings.Join(parts, "+")
}

func parseDirection(d string) (uint32, error) {
	d = strings.TrimSpace(d)
	if d == "" {
		return DirAny, nil
	}

	var mask uint32
	for _, part := range strings.Split(d, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		bit, ok := directionNames[part]
		if !ok {
			return 0, fmt.Errorf("unknown direction %q (valid: any, connect, bind, listen, accept, ingress, egress)", part)
		}
		// "any" is absorbing: if it appears anywhere, the rule is unscoped.
		if bit == DirAny {
			return DirAny, nil
		}
		mask |= bit
	}
	return mask, nil
}

func parsePortRange(pr string) (uint16, uint16, error) {
	parts := strings.Split(pr, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range format")
	}
	min, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return 0, 0, err
	}
	max, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return 0, 0, err
	}
	if min > max {
		return 0, 0, fmt.Errorf("min port > max port")
	}
	return uint16(min), uint16(max), nil
}

type PolicyGroup struct {
	Name       string          `yaml:"name"`
	Action     string          `yaml:"action"`
	KillSignal uint32          `yaml:"kill_signal,omitempty"`
	Binaries   []BinaryPolicy  `yaml:"binaries,omitempty"`
	Files      []FilePolicy    `yaml:"files,omitempty"`
	Networks   []NetworkPolicy `yaml:"networks,omitempty"`
}

type FilePolicy struct {
	Path            string   `yaml:"path"`
	OnlyInContainer bool     `yaml:"only_in_container,omitempty"`
	Ancestors       []string `yaml:"ancestors,omitempty"`
}

type SensorPolicy struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	Hook       string `yaml:"hook,omitempty"`
	Code       string `yaml:"code,omitempty"`
	ObjectPath string `yaml:"object_path,omitempty"`
}

type PolicyConfig struct {
	Policies []PolicyGroup  `yaml:"policies"`
	Sensors  []SensorPolicy `yaml:"sensors,omitempty"`
	// AutoBlock is the DAEMON-OWNED section: IPs flagged at runtime by the
	// XDP/ML sensor. Humans author `policies:`; the daemon author this.
	//
	// It is deliberately NOT processed by applyPolicy() — see the carve-out
	// there. These IPs go into the kernel LRU cache via autoBlocklist, which
	// is the sole authority over that map. If applyPolicy reconciled this
	// section it would fight the LRU: reconcile would re-inject every entry on
	// every reload and delete whatever LRU kept, destroying the eviction order.
	AutoBlock []string `yaml:"auto_block,omitempty"`
}

type DynamicSensor struct {
	Collection *ebpf.Collection
	Link       link.Link
	CodeHash   uint64 // Track code changes
}

type bpfEvent struct {
	PID    uint32
	Action uint32
	Target [256]byte
	Hook   [16]byte
}

type Event struct {
	PID       uint32 `json:"pid"`
	Action    uint32 `json:"action"`
	Target    string `json:"target"`
	Hook      string `json:"hook"`
	Direction string `json:"direction,omitempty"`
}

// networkHooks are the hooks whose ringbuf `target` field carries the packed
// binary endpoint encoding (raw IP + port + type-flag byte) rather than a
// NUL-terminated path string.
var networkHooks = map[string]string{
	"connect": "egress",  // we initiated an outbound connection
	"bind":    "ingress", // we claimed a local address:port
	"listen":  "ingress", // we entered LISTEN on a local address:port
	"accept":  "ingress", // a remote peer connected to us
}

func isNetworkHook(hook string) bool {
	_, ok := networkHooks[hook]
	return ok
}

func hookDirection(hook string) string {
	return networkHooks[hook]
}

var (
	activeSensors = make(map[string]*DynamicSensor)
	policyMu      sync.Mutex
)

const FnvOffsetBasis uint64 = 14695981039346656037
const FnvPrime uint64 = 1099511628211

// 64-bit FNV-1a Hash
func parseToKey(str string, maxLen int) uint64 {
	if len(str) > maxLen {
		str = str[:maxLen]
	}
	var hash uint64 = FnvOffsetBasis
	for i := 0; i < len(str); i++ {
		hash ^= uint64(str[i])
		hash *= FnvPrime
	}
	return hash
}

// clearPolicyMaps removed, replaced by diffing in applyPolicy

func loadPolicy(filename string) (*PolicyConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var p PolicyConfig
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func applyPolicy(p *PolicyConfig, objs *bpf.BpfObjects) {
	// NOTE: p.AutoBlock is intentionally NOT handled here.
	//
	// It targets dynamic_blocklist_v4/v6 (LRU_HASH), which autoBlocklist owns
	// exclusively. Reconciling it here would mean two authorities over one map:
	// this function's desired-vs-actual pass would delete LRU-retained entries
	// and re-Put every persisted IP on every reload, thrashing the cache and
	// destroying LRU ordering. The LRU decides what stays resident; the YAML
	// section is only the permanent record. Keep them separate.
	policyMu.Lock()
	defer policyMu.Unlock()

	log.Println("Applying new policy rules (eventual consistency)...")

	desiredBin := make(map[uint64]bool)
	desiredFile := make(map[uint64]bool)
	desiredPort := make(map[uint16]bool)
	desiredIp := make(map[uint32]bool)
	desiredIpv6 := make(map[bpf.BpfIpv6Key]bool)
	desiredIpv4Net := make(map[bpf.BpfIpv4NetworkKey]bool)
	desiredIpv6Net := make(map[bpf.BpfIpv6NetworkKey]bool)
	desiredIpv4Cidr := make(map[bpf.BpfIpv4LpmKey]bool)
	desiredIpv6Cidr := make(map[bpf.BpfIpv6LpmKey]bool)
	desiredBinLpm := make(map[bpf.BpfPathLpmKey]bool)
	desiredFileLpm := make(map[bpf.BpfPathLpmKey]bool)

	syncSensors(p, objs)

	for _, pol := range p.Policies {
		var action uint32 = 1 // default BLOCK
		if pol.Action == "kill" {
			action = 2
		} else if pol.Action == "alert" {
			action = 3
		} else if pol.Action == "deceive" {
			action = 4
		} else if pol.Action == "allow" {
			action = 5
		}

		for _, bin := range pol.Binaries {
			isLpm := strings.HasSuffix(bin.Path, "*")
			actualPath := bin.Path
			if isLpm {
				actualPath = strings.TrimSuffix(actualPath, "*")
			}

			var val bpf.BpfPolicyVal
			val.Action = action
			if pol.KillSignal != 0 {
				val.KillSignal = pol.KillSignal
			}

			if bin.OnlyInContainer {
				val.OnlyInContainer = 1
			}

			if len(bin.Ancestors) == 0 {
				val.BlockUnconditionally = 1
			} else {
				for i, ancestor := range bin.Ancestors {
					if i < 8 {
						val.AncestorHashes[i] = parseToKey(ancestor, 256)
					}
				}
			}

			if len(bin.Args) > 0 {
				for i, arg := range bin.Args {
					if i < 32 {
						val.BlockedArgHashes[i] = parseToKey(arg, 128)
					}
				}
			}

			if isLpm {
				var lpmKey bpf.BpfPathLpmKey
				lpmKey.Prefixlen = uint32(len(actualPath) * 8)
				for i := 0; i < len(actualPath) && i < 256; i++ {
					lpmKey.Data[i] = int8(actualPath[i])
				}
				if err := objs.BlockedBinariesLpm.Put(lpmKey, val); err != nil {
					log.Printf("Failed to block binary (LPM) %s: %v", actualPath, err)
				} else {
					desiredBinLpm[lpmKey] = true
					log.Printf("Blocked binary (LPM): %s*", actualPath)
				}
			} else {
				key := parseToKey(actualPath, 256)
				if err := objs.BlockedBinaries.Put(key, val); err != nil {
					log.Printf("Failed to block binary %s: %v", actualPath, err)
				} else {
					desiredBin[key] = true
					log.Printf("Blocked binary: %s", actualPath)
				}
			}
		}

		for _, file := range pol.Files {
			isLpm := strings.HasSuffix(file.Path, "*")
			actualPath := file.Path
			if isLpm {
				actualPath = strings.TrimSuffix(actualPath, "*")
			}

			var val bpf.BpfPolicyVal
			val.Action = action
			if pol.KillSignal != 0 {
				val.KillSignal = pol.KillSignal
			}

			if file.OnlyInContainer {
				val.OnlyInContainer = 1
			}

			if len(file.Ancestors) == 0 {
				val.BlockUnconditionally = 1
			} else {
				for i, ancestor := range file.Ancestors {
					if i < 8 {
						val.AncestorHashes[i] = parseToKey(ancestor, 256)
					}
				}
			}

			if isLpm {
				var lpmKey bpf.BpfPathLpmKey
				lpmKey.Prefixlen = uint32(len(actualPath) * 8)
				for i := 0; i < len(actualPath) && i < 256; i++ {
					lpmKey.Data[i] = int8(actualPath[i])
				}
				if err := objs.BlockedFilesLpm.Put(lpmKey, val); err != nil {
					log.Printf("Failed to block file (LPM) %s: %v", actualPath, err)
				} else {
					desiredFileLpm[lpmKey] = true
					log.Printf("Blocked file (LPM): %s*", actualPath)
				}
			} else {
				key := parseToKey(actualPath, 256)
				if err := objs.BlockedFiles.Put(key, val); err != nil {
					log.Printf("Failed to block file %s: %v", actualPath, err)
				} else {
					desiredFile[key] = true
					log.Printf("Blocked file: %s", actualPath)
				}
			}
		}

		for _, netPol := range pol.Networks {
			var val bpf.BpfPolicyVal
			val.Action = action
			if pol.KillSignal != 0 {
				val.KillSignal = pol.KillSignal
			}
			val.BlockUnconditionally = 1

			dirMask, err := parseDirection(netPol.Direction)
			if err != nil {
				log.Printf("Invalid direction in policy %q: %v (skipping rule)", pol.Name, err)
				continue
			}
			val.DirectionMask = dirMask

			if netPol.PortRange != "" {
				minP, maxP, err := parsePortRange(netPol.PortRange)
				if err != nil {
					log.Printf("Invalid port range %s: %v", netPol.PortRange, err)
				} else {
					val.MinPort = minP
					val.MaxPort = maxP
				}
			} else if netPol.Port != 0 {
				val.MinPort = netPol.Port
				val.MaxPort = netPol.Port
			}

			if netPol.CIDR != "" {
				ip, ipnet, err := net.ParseCIDR(netPol.CIDR)
				if err != nil {
					log.Printf("Invalid CIDR: %s", netPol.CIDR)
					continue
				}
				ones, _ := ipnet.Mask.Size()
				ip4 := ip.To4()
				if ip4 != nil {
					var cidrKey bpf.BpfIpv4LpmKey
					cidrKey.Prefixlen = uint32(ones)
					cidrKey.Data = binary.LittleEndian.Uint32(ip4)
					if err := objs.BlockedIpv4Cidr.Put(cidrKey, val); err != nil {
						log.Printf("Failed to block CIDR %s: %v", netPol.CIDR, err)
					} else {
						desiredIpv4Cidr[cidrKey] = true
						log.Printf("Blocked IPv4 CIDR: %s [dir=%s]", netPol.CIDR, dirLabel(dirMask))
					}
				} else {
					var cidrKey bpf.BpfIpv6LpmKey
					cidrKey.Prefixlen = uint32(ones)
					copy(cidrKey.Data[:], ip.To16())
					if err := objs.BlockedIpv6Cidr.Put(cidrKey, val); err != nil {
						log.Printf("Failed to block CIDR %s: %v", netPol.CIDR, err)
					} else {
						desiredIpv6Cidr[cidrKey] = true
						log.Printf("Blocked IPv6 CIDR: %s [dir=%s]", netPol.CIDR, dirLabel(dirMask))
					}
				}
			} else if netPol.IP != "" && netPol.Port != 0 {
				ip := net.ParseIP(netPol.IP)
				if ip == nil {
					log.Printf("Invalid IP address: %s", netPol.IP)
					continue
				}
				ip4 := ip.To4()
				if ip4 != nil {
					var netKey bpf.BpfIpv4NetworkKey
					netKey.Ip = binary.LittleEndian.Uint32(ip4)
					netKey.Port = netPol.Port
					if err := objs.BlockedIpv4Networks.Put(netKey, val); err != nil {
						log.Printf("Failed to block IPv4 network %s:%d: %v", netPol.IP, netPol.Port, err)
					} else {
						desiredIpv4Net[netKey] = true
						log.Printf("Blocked IPv4 network: %s:%d [dir=%s]", netPol.IP, netPol.Port, dirLabel(dirMask))
					}
				} else {
					var netKey bpf.BpfIpv6NetworkKey
					copy(netKey.Ip[:], ip.To16())
					netKey.Port = netPol.Port
					if err := objs.BlockedIpv6Networks.Put(netKey, val); err != nil {
						log.Printf("Failed to block IPv6 network [%s]:%d: %v", netPol.IP, netPol.Port, err)
					} else {
						desiredIpv6Net[netKey] = true
						log.Printf("Blocked IPv6 network: [%s]:%d [dir=%s]", netPol.IP, netPol.Port, dirLabel(dirMask))
					}
				}
			} else if netPol.IP != "" {
				ip := net.ParseIP(netPol.IP)
				if ip == nil {
					log.Printf("Invalid IP address: %s", netPol.IP)
					continue
				}

				ip4 := ip.To4()
				if ip4 != nil {
					ipKey := binary.LittleEndian.Uint32(ip4)
					if err := objs.BlockedIps.Put(ipKey, val); err != nil {
						log.Printf("Failed to block IPv4 %s: %v", netPol.IP, err)
					} else {
						desiredIp[ipKey] = true
						log.Printf("Blocked IPv4: %s [dir=%s]", netPol.IP, dirLabel(dirMask))
					}
				} else {
					var ipKey bpf.BpfIpv6Key
					copy(ipKey.Addr[:], ip.To16())
					if err := objs.BlockedIpsV6.Put(ipKey, val); err != nil {
						log.Printf("Failed to block IPv6 %s: %v", netPol.IP, err)
					} else {
						desiredIpv6[ipKey] = true
						log.Printf("Blocked IPv6: %s [dir=%s]", netPol.IP, dirLabel(dirMask))
					}
				}
			} else if netPol.PortRange != "" || netPol.Port != 0 {
				// blocked_ports is a HASH keyed by a single u16; the kernel does
				// one exact-key lookup and cannot scan a range. So a range must
				// be materialized as one entry per port. A single port is just
				// the degenerate range [port, port].
				lo, hi := netPol.Port, netPol.Port
				if netPol.PortRange != "" {
					lo, hi = val.MinPort, val.MaxPort
				}
				// If a port_range was given but failed to parse, MinPort/MaxPort
				// remain 0; skip rather than inserting a bogus port-0 entry.
				if lo == 0 && hi == 0 {
					log.Printf("Skipping network rule in %q: no valid port or range", pol.Name)
					continue
				}

				// Give each entry an exact-match window (min==max==p) so the
				// kernel's is_policy_valid() secondary check passes for that port.
				portVal := val
				var blocked, failed int
				for p := int(lo); p <= int(hi); p++ {
					portVal.MinPort = uint16(p)
					portVal.MaxPort = uint16(p)
					if err := objs.BlockedPorts.Put(uint16(p), portVal); err != nil {
						failed++
						continue
					}
					desiredPort[uint16(p)] = true
					blocked++
				}
				if failed > 0 {
					log.Printf("Blocked ports %d-%d [dir=%s]: %d ok, %d failed", lo, hi, dirLabel(dirMask), blocked, failed)
				} else if lo == hi {
					log.Printf("Blocked port: %d [dir=%s]", lo, dirLabel(dirMask))
				} else {
					log.Printf("Blocked port range: %d-%d (%d ports) [dir=%s]", lo, hi, blocked, dirLabel(dirMask))
				}
			}
		}
	}

	var valStruct bpf.BpfPolicyVal
	// Clean up Binaries
	iterBin := objs.BlockedBinaries.Iterate()
	var key64 uint64
	var val bpf.BpfPolicyVal
	for iterBin.Next(&key64, &val) {
		if !desiredBin[key64] {
			objs.BlockedBinaries.Delete(key64)
		}
	}

	iterBinLpm := objs.BlockedBinariesLpm.Iterate()
	var lpmKey bpf.BpfPathLpmKey
	for iterBinLpm.Next(&lpmKey, &val) {
		if !desiredBinLpm[lpmKey] {
			objs.BlockedBinariesLpm.Delete(lpmKey)
		}
	}

	// Clean up Files
	iterFile := objs.BlockedFiles.Iterate()
	for iterFile.Next(&key64, &val) {
		if !desiredFile[key64] {
			objs.BlockedFiles.Delete(key64)
		}
	}

	iterFileLpm := objs.BlockedFilesLpm.Iterate()
	for iterFileLpm.Next(&lpmKey, &val) {
		if !desiredFileLpm[lpmKey] {
			objs.BlockedFilesLpm.Delete(lpmKey)
		}
	}

	var key16 uint16
	iterPort := objs.BlockedPorts.Iterate()
	for iterPort.Next(&key16, &valStruct) {
		if !desiredPort[key16] {
			objs.BlockedPorts.Delete(key16)
		}
	}

	var key32 uint32
	iterIp := objs.BlockedIps.Iterate()
	for iterIp.Next(&key32, &valStruct) {
		if !desiredIp[key32] {
			objs.BlockedIps.Delete(key32)
		}
	}

	var keyV6 bpf.BpfIpv6Key
	iterV6 := objs.BlockedIpsV6.Iterate()
	for iterV6.Next(&keyV6, &valStruct) {
		if !desiredIpv6[keyV6] {
			objs.BlockedIpsV6.Delete(keyV6)
		}
	}

	var keyV4Net bpf.BpfIpv4NetworkKey
	iterV4Net := objs.BlockedIpv4Networks.Iterate()
	for iterV4Net.Next(&keyV4Net, &valStruct) {
		if !desiredIpv4Net[keyV4Net] {
			objs.BlockedIpv4Networks.Delete(keyV4Net)
		}
	}

	var keyV6Net bpf.BpfIpv6NetworkKey
	iterV6Net := objs.BlockedIpv6Networks.Iterate()
	for iterV6Net.Next(&keyV6Net, &valStruct) {
		if !desiredIpv6Net[keyV6Net] {
			objs.BlockedIpv6Networks.Delete(keyV6Net)
		}
	}

	var keyV4Cidr bpf.BpfIpv4LpmKey
	iterV4Cidr := objs.BlockedIpv4Cidr.Iterate()
	for iterV4Cidr.Next(&keyV4Cidr, &valStruct) {
		if !desiredIpv4Cidr[keyV4Cidr] {
			objs.BlockedIpv4Cidr.Delete(keyV4Cidr)
		}
	}

	var keyV6Cidr bpf.BpfIpv6LpmKey
	iterV6Cidr := objs.BlockedIpv6Cidr.Iterate()
	for iterV6Cidr.Next(&keyV6Cidr, &valStruct) {
		if !desiredIpv6Cidr[keyV6Cidr] {
			objs.BlockedIpv6Cidr.Delete(keyV6Cidr)
		}
	}
}

func getExePath(pid int) (string, error) {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	return exePath, nil
}

func getPpid(pid int) (int, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	parts := strings.Fields(string(stat))
	if len(parts) > 3 {
		ppid, err := strconv.Atoi(parts[3])
		if err == nil {
			return ppid, nil
		}
	}
	return 0, fmt.Errorf("could not parse ppid")
}

func bootstrapProcessTree(objs *bpf.BpfObjects) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("Failed to read /proc: %v", err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}

		exePath, err := getExePath(pid)
		if err != nil {
			continue // Could be kernel thread or permission denied
		}

		var pinfo bpf.BpfProcessInfo
		pinfo.ExeHash = parseToKey(exePath, 256)

		currPid := pid
		for i := 0; i < 8; i++ {
			ppid, err := getPpid(currPid)
			if err != nil || ppid == 0 || ppid == 1 {
				break
			}
			pExePath, err := getExePath(ppid)
			if err == nil {
				pinfo.Ancestors[i] = parseToKey(pExePath, 256)
			}
			currPid = ppid
		}

		if err := objs.Processes.Put(uint32(pid), pinfo); err != nil {
			log.Printf("Failed to bootstrap PID %d: %v", pid, err)
		}
	}
	log.Printf("Bootstrapped process tree into eBPF map")
}

// ============================================================================
// DYNAMIC AUTO-BLOCKLIST
//
// IPs flagged at RUNTIME (by the XDP/ML sensor or any detector) are recorded in
// the `auto_block:` section of policy.yaml and cached in a kernel LRU map.
//
//   Userspace (policy.yaml `auto_block:`):  permanent, unbounded, on disk.
//                                           The source of truth. No eviction.
//   Kernel (dynamic_blocklist_v4/v6):       LRU_HASH, bounded hot cache.
//                                           Evicts the COLDEST entry when full.
//
// Persist-before-inject: an IP is written to policy.yaml BEFORE being pushed to
// the kernel. So an LRU eviction never loses information — the IP stays on
// permanent record, is re-injected at startup, and re-injected if it reoffends.
//
// Two mechanisms deliberately kept apart:
//   - applyPolicy() owns the `policies:` section and the static HASH/LPM maps.
//     It does NOT touch `auto_block:` (see the carve-out note there).
//   - autoBlocklist owns `auto_block:` and the LRU maps. It does NOT touch
//     `policies:`.
// Writes here are marked via markSelfWrite() so the fsnotify policy watcher
// ignores daemon-originated changes and does not trigger a reload storm.
// ============================================================================

const autoBlockDefaultAction = uint32(1) // ACTION_BLOCK

type autoBlocklist struct {
	mu        sync.Mutex
	permanent map[string]bool // every IP ever flagged (mirrors auto_block: on disk)
	path      string          // policy.yaml
	objs      *bpf.BpfObjects

	// selfWrite guards against our own writes re-triggering the policy watcher.
	selfWriteMu sync.Mutex
	selfWrites  int
}

func newAutoBlocklist(policyPath string, objs *bpf.BpfObjects) *autoBlocklist {
	return &autoBlocklist{
		permanent: make(map[string]bool),
		path:      policyPath,
		objs:      objs,
	}
}

// markSelfWrite records that the daemon is about to write policy.yaml, so the
// watcher can swallow the resulting fsnotify event instead of reloading.
func (a *autoBlocklist) markSelfWrite() {
	a.selfWriteMu.Lock()
	a.selfWrites++
	a.selfWriteMu.Unlock()
}

// consumeSelfWrite reports whether this fsnotify event was caused by us. If so
// it consumes the marker and returns true (caller should skip the reload).
func (a *autoBlocklist) consumeSelfWrite() bool {
	a.selfWriteMu.Lock()
	defer a.selfWriteMu.Unlock()
	if a.selfWrites > 0 {
		a.selfWrites--
		return true
	}
	return false
}

// load reads the auto_block: section from policy.yaml and re-injects every IP
// into the kernel LRU cache. Called at startup so restarts forget nothing.
// If the permanent record exceeds the kernel cache size, the excess simply
// stays on record and is re-injected when it next offends — no data is lost.
func (a *autoBlocklist) load(p *PolicyConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var reinjected int
	for _, ipStr := range p.AutoBlock {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		a.permanent[ipStr] = true
		if err := a.injectKernel(ipStr); err == nil {
			reinjected++
		}
	}
	if len(a.permanent) > 0 {
		log.Printf("auto-block: %d permanent entries in %s, re-injected %d into kernel LRU cache",
			len(a.permanent), filepath.Base(a.path), reinjected)
	}
}

// syncFromPolicy refreshes the in-memory permanent set after an admin edits
// policy.yaml by hand (e.g. deleting an auto_block entry to un-block an IP).
// Entries removed from the file are dropped from the kernel LRU too, so a hand
// edit is honoured. This is the ONE place auto_block entries get deleted.
func (a *autoBlocklist) syncFromPolicy(p *PolicyConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()

	desired := make(map[string]bool, len(p.AutoBlock))
	for _, ipStr := range p.AutoBlock {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr != "" {
			desired[ipStr] = true
		}
	}

	// Removed by hand -> drop from kernel cache and permanent set.
	for ipStr := range a.permanent {
		if !desired[ipStr] {
			a.deleteKernel(ipStr)
			delete(a.permanent, ipStr)
			log.Printf("auto-block: %s removed from policy, un-blocked", ipStr)
		}
	}
	// Added by hand -> inject.
	for ipStr := range desired {
		if !a.permanent[ipStr] {
			a.permanent[ipStr] = true
			if err := a.injectKernel(ipStr); err != nil {
				log.Printf("auto-block: inject %s: %v", ipStr, err)
			} else {
				log.Printf("auto-block: %s added via policy edit", ipStr)
			}
		}
	}
}

// add flags an IP: appends it to policy.yaml's auto_block: section FIRST, then
// pushes it to the kernel LRU cache. Safe to call repeatedly for the same IP.
func (a *autoBlocklist) add(ipStr string) error {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return fmt.Errorf("invalid IP %q", ipStr)
	}
	canonical := ip.String()

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.permanent[canonical] {
		// Already on record; just refresh the kernel cache (it may have been evicted).
		return a.injectKernel(canonical)
	}
	a.permanent[canonical] = true

	// Persist BEFORE injecting. If we die between the two, startup load()
	// re-injects from the file — never the reverse.
	if err := a.persistToPolicy(canonical); err != nil {
		log.Printf("auto-block: failed to persist %s to %s: %v", canonical, a.path, err)
		// Continue: an in-kernel block is still better than none for this run.
	}

	if err := a.injectKernel(canonical); err != nil {
		return fmt.Errorf("inject %s into kernel cache: %w", canonical, err)
	}
	log.Printf("auto-block: flagged %s (permanent=%d)", canonical, len(a.permanent))
	return nil
}

// persistToPolicy appends one IP to the auto_block: sequence in policy.yaml,
// editing the YAML node tree so the rest of the file — including comments —
// survives. Caller holds a.mu.
func (a *autoBlocklist) persistToPolicy(ipStr string) error {
	data, err := os.ReadFile(a.path)
	if err != nil {
		return err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("unexpected policy structure in %s", a.path)
	}
	doc := root.Content[0]

	entry := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ipStr}

	var seq *yaml.Node
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "auto_block" {
			seq = doc.Content[i+1]
			break
		}
	}
	if seq == nil {
		// Section absent: create it, annotated so operators know who owns it.
		key := &yaml.Node{
			Kind:        yaml.ScalarNode,
			Tag:         "!!str",
			Value:       "auto_block",
			HeadComment: "Managed by bpf-sec-daemon. IPs flagged at runtime by the\nsensor. Cached in a kernel LRU map; this list is the permanent\nrecord. Remove a line here to un-block that IP on next reload.",
		}
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		doc.Content = append(doc.Content, key, seq)
	}
	seq.Content = append(seq.Content, entry)

	out, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}

	// Atomic replace so a crash mid-write can't truncate the policy file, and
	// so readers never see a half-written file.
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	a.markSelfWrite() // rename fires the watcher; tell it to ignore this one
	if err := os.Rename(tmp, a.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// injectKernel pushes one IP into the appropriate kernel LRU map. Caller holds
// a.mu. Action=BLOCK, no port/direction constraints (matches any port, any
// hook). LRU evicts the coldest entry if the map is full.
func (a *autoBlocklist) injectKernel(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP %q", ipStr)
	}

	var val bpf.BpfPolicyVal
	val.Action = autoBlockDefaultAction
	val.BlockUnconditionally = 1
	// MinPort/MaxPort 0 => any port. DirectionMask 0 => any hook.

	if ip4 := ip.To4(); ip4 != nil {
		key := binary.LittleEndian.Uint32(ip4)
		return a.objs.AutoblockV4.Put(key, val)
	}
	var key bpf.BpfIpv6Key
	copy(key.Addr[:], ip.To16())
	return a.objs.AutoblockV6.Put(key, val)
}

// deleteKernel removes one IP from the kernel LRU cache. Caller holds a.mu.
func (a *autoBlocklist) deleteKernel(ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}
	if ip4 := ip.To4(); ip4 != nil {
		a.objs.AutoblockV4.Delete(binary.LittleEndian.Uint32(ip4))
		return
	}
	var key bpf.BpfIpv6Key
	copy(key.Addr[:], ip.To16())
	a.objs.AutoblockV6.Delete(key)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	policyFile := "policy.yaml"
	if len(os.Args) > 1 {
		policyFile = os.Args[1]
	}

	var objs bpf.BpfObjects
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	bootstrapProcessTree(&objs)

	lExec, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictExec,
	})
	if err != nil {
		log.Fatalf("attaching lsm restrict_exec: %v", err)
	}
	defer lExec.Close()

	lCommit, err := link.AttachLSM(link.LSMOptions{
		Program: objs.CommitCreds,
	})
	if err != nil {
		log.Fatalf("attaching lsm commit_creds: %v", err)
	}
	defer lCommit.Close()

	lFile, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictFile,
	})
	if err != nil {
		log.Fatalf("attaching lsm restrict_file: %v", err)
	}
	defer lFile.Close()

	lTaskAlloc, err := link.AttachLSM(link.LSMOptions{Program: objs.TrackTaskAlloc})
	if err != nil {
		log.Fatalf("attaching lsm track_task_alloc: %v", err)
	}
	defer lTaskAlloc.Close()

	lTaskFree, err := link.AttachLSM(link.LSMOptions{Program: objs.TrackTaskFree})
	if err != nil {
		log.Fatalf("attaching lsm track_task_free: %v", err)
	}
	defer lTaskFree.Close()

	lFileFree, err := link.AttachLSM(link.LSMOptions{Program: objs.TrackFileFree})
	if err != nil {
		log.Fatalf("attaching lsm track_file_free: %v", err)
	}
	defer lFileFree.Close()

	lRead, err := link.AttachTracing(link.TracingOptions{Program: objs.VfsReadExit})
	if err != nil {
		log.Fatalf("attaching fexit vfs_read: %v", err)
	}
	defer lRead.Close()

	lWrite, err := link.AttachTracing(link.TracingOptions{Program: objs.VfsWriteExit})
	if err != nil {
		log.Fatalf("attaching fexit vfs_write: %v", err)
	}
	defer lWrite.Close()

	lTraceExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint sys_enter_execve: %v", err)
	}
	defer lTraceExecve.Close()

	lNet, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictConnect,
	})
	if err != nil {
		log.Fatalf("attaching lsm restrict_connect: %v", err)
	}
	defer lNet.Close()

	// --- Inbound / server-side network enforcement ---
	// restrict_connect above only governs egress initiation. These three cover
	// the server side: what we may bind/listen on, and which remote peers we
	// accept (and therefore which peers ever receive our outgoing responses).
	lBind, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictBind,
	})
	if err != nil {
		log.Fatalf("attaching lsm restrict_bind: %v", err)
	}
	defer lBind.Close()

	lListen, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictListen,
	})
	if err != nil {
		log.Fatalf("attaching lsm restrict_listen: %v", err)
	}
	defer lListen.Close()

	lAccept, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictAccept,
	})
	if err != nil {
		log.Fatalf("attaching lsm restrict_accept: %v", err)
	}
	defer lAccept.Close()

	p, err := loadPolicy(policyFile)
	if err != nil {
		log.Fatalf("Failed to load initial policy: %v", err)
	}
	applyPolicy(p, &objs)

	// Dynamic auto-blocklist: permanent record lives in policy.yaml's
	// auto_block: section; kernel LRU map is the hot cache.
	autoBlock := newAutoBlocklist(policyFile, &objs)
	autoBlock.load(p)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	policyDir := filepath.Dir(policyFile)
	policyBase := filepath.Base(policyFile)

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if filepath.Base(event.Name) == policyBase && (event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Rename == fsnotify.Rename) {
					// Swallow events caused by our own auto_block writes: they
					// carry no admin changes, and reloading on every flagged IP
					// would be a reload storm under attack.
					if autoBlock.consumeSelfWrite() {
						continue
					}
					log.Println("Policy file changed, reloading...")
					newP, err := loadPolicy(policyFile)
					if err != nil {
						log.Printf("Error reloading policy: %v", err)
						continue
					}
					applyPolicy(newP, &objs)
					// Honour hand-edits to auto_block: (e.g. an admin deleting a
					// line to un-block an IP). applyPolicy deliberately ignores
					// that section, so reconcile it here instead.
					autoBlock.syncFromPolicy(newP)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(policyDir)
	if err != nil {
		log.Fatal(err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
					return
				}
				log.Printf("Error reading from ringbuf: %s", err)
				continue
			}

			var evt bpfEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			targetEnd := bytes.IndexByte(evt.Target[:], 0)
			if targetEnd == -1 {
				targetEnd = len(evt.Target)
			}
			hookEnd := bytes.IndexByte(evt.Hook[:], 0)
			if hookEnd == -1 {
				hookEnd = len(evt.Hook)
			}

			targetStr := string(evt.Target[:targetEnd])
			hookStr := string(evt.Hook[:hookEnd])

			// Decode network events. All four network hooks (connect, bind,
			// listen, accept) use the same packed target encoding.
			if isNetworkHook(hookStr) && len(evt.Target) >= 7 {
				if evt.Target[6] == 0x01 {
					// IPv4
					ip := net.IPv4(evt.Target[0], evt.Target[1], evt.Target[2], evt.Target[3])
					port := binary.LittleEndian.Uint16(evt.Target[4:6])
					targetStr = fmt.Sprintf("%s:%d", ip.String(), port)
				} else if len(evt.Target) >= 19 && evt.Target[18] == 0x02 {
					// IPv6
					var ipKey bpf.BpfIpv6Key
					copy(ipKey.Addr[:], evt.Target[0:16])
					ip := net.IP(ipKey.Addr[:])
					port := binary.LittleEndian.Uint16(evt.Target[16:18])
					targetStr = fmt.Sprintf("[%s]:%d", ip.String(), port)
				}
			} else if hookStr == "file_io_summary" && len(evt.Target) >= 17 {
				if evt.Target[16] == 0x03 {
					bytesRead := binary.LittleEndian.Uint64(evt.Target[0:8])
					bytesWritten := binary.LittleEndian.Uint64(evt.Target[8:16])

					tEnd := bytes.IndexByte(evt.Target[17:], 0)
					if tEnd == -1 {
						tEnd = len(evt.Target) - 17
					}
					filename := string(evt.Target[17 : 17+tEnd])

					targetStr = fmt.Sprintf(`{"file":"%s","bytes_read":%d,"bytes_written":%d}`, filename, bytesRead, bytesWritten)
				}
			}

			event := Event{
				PID:       evt.PID,
				Action:    evt.Action,
				Target:    targetStr,
				Hook:      hookStr,
				Direction: hookDirection(hookStr),
			}

			jsonBytes, _ := json.Marshal(event)
			fmt.Println(string(jsonBytes))
		}
	}()

	log.Println("BPF LSM Security Tool is running! Try running a blocked binary. Press Ctrl+C to exit.")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("Shutting down...")
}

func syncSensors(p *PolicyConfig, objs *bpf.BpfObjects) {
	desired := make(map[string]bool)

	for _, s := range p.Sensors {
		desired[s.Name] = true
		codeHash := parseToKey(s.Code, 9999999) // No truncation for full code hash

		if existing, exists := activeSensors[s.Name]; exists {
			if existing.CodeHash == codeHash {
				continue // Same code, skip
			}
			log.Printf("Sensor %s code changed, reloading...", s.Name)
			existing.Link.Close()
			existing.Collection.Close()
			delete(activeSensors, s.Name)
		}

		log.Printf("Compiling dynamic sensor: %s", s.Name)
		err := loadDynamicSensor(s, objs, codeHash)
		if err != nil {
			log.Printf("Failed to load sensor %s: %v", s.Name, err)
		}
	}

	for name, sensor := range activeSensors {
		if !desired[name] {
			log.Printf("Unloading dynamic sensor: %s", name)
			sensor.Link.Close()
			sensor.Collection.Close()
			delete(activeSensors, name)
		}
	}
}

func loadDynamicSensor(s SensorPolicy, objs *bpf.BpfObjects, codeHash uint64) error {
	var oFile string

	// Sanitize Name and Hook to prevent C Code Injection
	validName := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !validName.MatchString(s.Name) {
		return fmt.Errorf("invalid sensor name (must be alphanumeric/underscore only): %s", s.Name)
	}
	if s.Hook != "" && !validName.MatchString(strings.ReplaceAll(s.Hook, "-", "_")) { // allow some common hook chars if needed, but strictly limit
		return fmt.Errorf("invalid sensor hook (must be alphanumeric/underscore only): %s", s.Hook)
	}

	if s.ObjectPath != "" {
		oFile = s.ObjectPath
	} else {
		tmpDir, err := os.MkdirTemp("", "bpf-sensor-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)

		cFile := filepath.Join(tmpDir, "sensor.c")
		oFile = filepath.Join(tmpDir, "sensor.o")

		if err := os.WriteFile(filepath.Join(tmpDir, "vmlinux.h"), bpf.VmlinuxH, 0644); err != nil {
			return fmt.Errorf("failed to write vmlinux.h: %v", err)
		}

		var secName string
		var progDef string
		if s.Type == "xdp" {
			secName = "xdp"
			progDef = fmt.Sprintf("int %s(struct xdp_md *ctx)", s.Name)
		} else {
			secName = "lsm/" + s.Hook
			progDef = fmt.Sprintf("int BPF_PROG(%s)", s.Name)
		}

		cCode := fmt.Sprintf(`
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
    __u32 pid;
    __u32 action;
    char target[256];
    char hook[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("%s")
%s {
    %s
}

char LICENSE[] SEC("license") = "GPL";
`, secName, progDef, s.Code)

		if err := os.WriteFile(cFile, []byte(cCode), 0644); err != nil {
			return err
		}

		cwd, _ := os.Getwd()
		archArgs := []string{"-O2", "-g", "-target", "bpf", "-I" + cwd}
		if _, err := os.Stat("/usr/include/x86_64-linux-gnu"); err == nil {
			archArgs = append(archArgs, "-I/usr/include/x86_64-linux-gnu")
		} else if _, err := os.Stat("/usr/include/aarch64-linux-gnu"); err == nil {
			archArgs = append(archArgs, "-I/usr/include/aarch64-linux-gnu")
		}
		archArgs = append(archArgs, "-c", cFile, "-o", oFile)
		cmd := exec.Command("clang", archArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("clang error: %s\n%s", err, out)
		}
	}

	spec, err := ebpf.LoadCollectionSpec(oFile)
	if err != nil {
		return fmt.Errorf("loading spec: %v", err)
	}

	if s.Hook != "" && spec.Programs[s.Name] != nil {
		if s.Type == "lsm" {
			spec.Programs[s.Name].AttachTo = "bpf_lsm_" + s.Hook
		} else if s.Type == "fexit" || s.Type == "fentry" {
			spec.Programs[s.Name].AttachTo = s.Hook
		}
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: make(map[string]*ebpf.Map),
	}
	if spec.Maps["events"] != nil {
		opts.MapReplacements["events"] = objs.Events
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("loading collection: %v", err)
	}

	prog := coll.Programs[s.Name]
	if prog == nil {
		coll.Close()
		return fmt.Errorf("program %s not found in elf", s.Name)
	}

	var l link.Link
	if s.Type == "lsm" {
		l, err = link.AttachLSM(link.LSMOptions{Program: prog})
	} else if s.Type == "fexit" || s.Type == "fentry" {
		l, err = link.AttachTracing(link.TracingOptions{Program: prog})
	} else if s.Type == "xdp" {
		iface, ifaceErr := net.InterfaceByName(s.Hook)
		if ifaceErr != nil {
			coll.Close()
			return fmt.Errorf("finding interface %s: %v", s.Hook, ifaceErr)
		}
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
		})
	} else {
		l, err = link.AttachLSM(link.LSMOptions{Program: prog}) // Default
	}

	if err != nil {
		coll.Close()
		return fmt.Errorf("attaching hook: %v", err)
	}

	activeSensors[s.Name] = &DynamicSensor{
		Collection: coll,
		Link:       l,
		CodeHash:   codeHash,
	}

	log.Printf("Successfully attached dynamic sensor: %s", s.Name)
	return nil
}