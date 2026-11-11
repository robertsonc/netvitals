package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const version = "1.0.0"

// state is what the agent remembers between runs. The key is an opaque value issued by the
// controller at enrolment; it is not signed and proves nothing beyond "this agent enrolled".
type state struct {
	Controller string `json:"controller"`
	Instance   string `json:"instance"` // random, generated once: lets a reinstall keep its identity
	AgentID    string `json:"agent_id"`
	Key        string `json:"key"`
}

func loadState(path string) state {
	var s state
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func (s state) save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type agent struct {
	st        state
	statePath string
	token     string
	name      string
	client    *http.Client
	out       *outbox
	refl      *reflector
	legs      map[uint32]*sendLeg
	cfgRev    int64
	started   time.Time
	lastOK    time.Time
	offset    int64 // controller clock minus local clock, ns (best of recent exchanges)
	offRTT    int64
	offAge    int
	orphaned  bool
}

type agentCfg struct {
	Rev     int64     `json:"rev"`
	Send    []legCfg  `json:"send"`
	Reflect []reflCfg `json:"reflect"`
}

type syncReq struct {
	Seq    int64     `json:"seq"`
	TSend  int64     `json:"t_send"`
	CfgRev int64     `json:"cfg_rev"`
	Offset int64     `json:"ctl_offset_ns"`
	OffRTT int64     `json:"ctl_rtt_ns"`
	Status agentStat `json:"status"`
	Tx     []txRec   `json:"tx"`
	Rx     []rxRec   `json:"rx"`
	Events []outage  `json:"events"`
}

type agentStat struct {
	Version  string            `json:"version"`
	Hostname string            `json:"hostname"`
	OS       string            `json:"os"`
	Arch     string            `json:"arch"`
	Addrs    []string          `json:"addrs"`
	UptimeS  int64             `json:"uptime_s"`
	KernelTS bool              `json:"kernel_ts"`
	Clock    string            `json:"clock"`
	Backlog  int               `json:"backlog"`
	Legs     map[string]string `json:"legs"`    // leg id -> problem, "" when healthy
	NoDSCP   []uint32          `json:"no_dscp"` // legs whose DSCP marking the OS did not accept
	Problems []string          `json:"problems"`
	Orphaned bool              `json:"orphaned"`
}

type syncResp struct {
	TRecv  int64     `json:"t_recv"`
	TReply int64     `json:"t_reply"`
	CfgRev int64     `json:"cfg_rev"`
	Cfg    *agentCfg `json:"cfg"`
	SyncMs int       `json:"sync_ms"`
	Error  string    `json:"error"`
}

// localAddrs lists this host's usable IPv4 addresses.
func localAddrs() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip := n.IP.To4(); ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				out = append(out, ip.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

func (a *agent) post(path string, in, out any, auth bool) (int, error) {
	body, _ := json.Marshal(in)
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(a.st.Controller, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth {
		req.Header.Set("X-Agent-Id", a.st.AgentID)
		req.Header.Set("X-Agent-Key", a.st.Key)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if err := json.Unmarshal(raw, out); err != nil && resp.StatusCode < 300 {
		return resp.StatusCode, fmt.Errorf("controller answered %d with something that is not JSON", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

var errRejected = errors.New("rejected")

// enroll trades the join token for an agent identity. Safe to repeat: the same instance id
// always maps to the same agent on the controller.
func (a *agent) enroll() error {
	if a.st.Instance == "" {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		a.st.Instance = hex.EncodeToString(b)
	}
	host, _ := os.Hostname()
	var out struct {
		AgentID string `json:"agent_id"`
		Key     string `json:"key"`
		Name    string `json:"name"`
		Error   string `json:"error"`
	}
	code, err := a.post("/api/agent/enroll", map[string]any{
		"token": a.token, "instance": a.st.Instance, "name": a.name, "hostname": host,
		"os": runtime.GOOS, "arch": runtime.GOARCH, "version": version, "addrs": localAddrs(),
	}, &out, false)
	if err != nil {
		return fmt.Errorf("cannot reach the controller at %s: %w", a.st.Controller, err)
	}
	if code != 200 {
		return fmt.Errorf("%w: controller refused enrolment (HTTP %d): %s", errRejected, code, out.Error)
	}
	a.st.AgentID, a.st.Key = out.AgentID, out.Key
	if err := a.st.save(a.statePath); err != nil {
		logf("warning: could not save %s (%v); the agent will re-enrol on restart", a.statePath, err)
	}
	logf("enrolled as %s (%s)", out.Name, out.AgentID)
	return nil
}

func (a *agent) apply(c *agentCfg) {
	want := map[uint32]legCfg{}
	for _, l := range c.Send {
		if err := l.validate(); err != nil {
			logf("ignoring %v", err)
			continue
		}
		want[l.Leg] = l
	}
	for id, l := range a.legs {
		w, ok := want[id]
		if ok && w == l.cfg {
			continue
		}
		if ok {
			l.close() // changed: let the old one finish before its replacement reuses the leg id
		} else {
			go l.close() // removed: waiting for in-flight answers must not stall the control loop
		}
		delete(a.legs, id)
	}
	for id, w := range want {
		if a.legs[id] == nil {
			a.legs[id] = startLeg(w, a.out)
		}
	}
	a.refl.apply(c.Reflect)
	a.cfgRev = c.Rev
	logf("config %d applied: sending %d leg(s), answering %d", c.Rev, len(want), len(c.Reflect))
}

const batchMax = 4000

func (a *agent) syncOnce(seq int64) error {
	o := a.out
	o.mu.Lock()
	nt, nr, ne := min(len(o.tx), batchMax), min(len(o.rx), batchMax), min(len(o.ev), batchMax)
	req := syncReq{Seq: seq, CfgRev: a.cfgRev, Offset: a.offset, OffRTT: a.offRTT,
		Tx: append([]txRec(nil), o.tx[:nt]...), Rx: append([]rxRec(nil), o.rx[:nr]...),
		Events: append([]outage(nil), o.ev[:ne]...)}
	backlog := len(o.tx) + len(o.rx) + len(o.ev)
	o.mu.Unlock()

	host, _ := os.Hostname()
	req.Status = agentStat{Version: version, Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Addrs: localAddrs(), UptimeS: int64(time.Since(a.started).Seconds()), KernelTS: kernelRxStamps,
		Clock: clockSource(), Backlog: backlog, Legs: map[string]string{}, Problems: a.refl.problems(),
		Orphaned: a.orphaned}
	for id, l := range a.legs {
		req.Status.Legs[fmt.Sprint(id)] = l.errMsg.Load().(string)
		if l.cfg.DSCP != 0 && !l.dscpOK.Load() {
			req.Status.NoDSCP = append(req.Status.NoDSCP, id)
		}
	}

	var resp syncResp
	req.TSend = nowNs()
	code, err := a.post("/api/agent/sync", &req, &resp, true)
	tResp := nowNs()
	if err != nil {
		return err
	}
	if code == 401 || code == 403 {
		return errRejected
	}
	if code != 200 {
		return fmt.Errorf("controller answered HTTP %d: %s", code, resp.Error)
	}
	// The records are stored under idempotent keys on the controller, so dropping them only
	// after a 200 can never double count.
	o.mu.Lock()
	o.tx, o.rx, o.ev = o.tx[nt:], o.rx[nr:], o.ev[ne:]
	o.mu.Unlock()

	// NTP-style offset to the controller's clock; keep the exchange with the least round trip.
	rtt := (tResp - req.TSend) - (resp.TReply - resp.TRecv)
	a.offAge++
	if resp.TRecv != 0 && (a.offRTT == 0 || rtt <= a.offRTT || a.offAge > 120) {
		a.offset = ((resp.TRecv - req.TSend) + (resp.TReply - tResp)) / 2
		a.offRTT, a.offAge = rtt, 0
	}
	if resp.Cfg != nil && resp.Cfg.Rev != a.cfgRev {
		a.apply(resp.Cfg)
	}
	return nil
}

// run is the control loop: upload results, pick up configuration, once a second. Measurement
// keeps going and results queue up while the controller is unreachable, which is the normal
// case when the control channel rides the very fabric being broken.
func (a *agent) run() error {
	const orphanAfter = 15 * time.Minute
	a.started, a.lastOK = time.Now(), time.Now()
	if a.st.AgentID == "" {
		for {
			err := a.enroll()
			if err == nil {
				break
			}
			if errors.Is(err, errRejected) {
				return err
			}
			logf("%v; retrying in 5 s", err)
			time.Sleep(5 * time.Second)
		}
	}
	fails := 0
	for seq := int64(1); ; seq++ {
		err := a.syncOnce(seq)
		switch {
		case err == nil:
			if fails > 0 {
				logf("controller reachable again after %d failed sync(s)", fails)
			}
			fails, a.lastOK, a.orphaned = 0, time.Now(), false
		case errors.Is(err, errRejected):
			logf("controller no longer recognises this agent; enrolling again")
			a.st.AgentID, a.st.Key = "", ""
			if e := a.enroll(); e != nil {
				logf("%v", e)
				time.Sleep(5 * time.Second)
			}
		default:
			fails++
			if fails == 1 || fails%30 == 0 {
				logf("sync failed (%d in a row): %v", fails, err)
			}
			if !a.orphaned && time.Since(a.lastOK) > orphanAfter {
				logf("no contact with the controller for %s: stopping traffic generation", orphanAfter)
				for id, l := range a.legs {
					l.close()
					delete(a.legs, id)
				}
				a.cfgRev, a.orphaned = -1, true
			}
		}
		time.Sleep(time.Second)
	}
}
