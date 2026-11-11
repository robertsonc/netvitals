package main

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// relay is a UDP impairment box with known, deterministic behaviour, so the agent's numbers can
// be checked against ground truth: it drops every Nth packet per direction, adds a fixed delay
// per direction, and can blackhole everything for a while.
type relay struct {
	front, back        *net.UDPConn
	target             *net.UDPAddr
	client             atomic.Pointer[net.UDPAddr]
	fwdEvery, revEvery atomic.Int64 // drop every Nth, 0 = none
	fwdDelay, revDelay atomic.Int64 // ns
	blackhole          atomic.Bool
	fwdSeen, revSeen   atomic.Int64
	fwdDropped         atomic.Int64
	revDropped         atomic.Int64
	wg                 sync.WaitGroup
}

func newRelay(t *testing.T, targetPort int) *relay {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{front: front, back: back, target: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: targetPort}}
	pump := func(in *net.UDPConn, forward bool) {
		defer r.wg.Done()
		buf := make([]byte, maxPacket+64)
		for {
			n, from, err := in.ReadFromUDP(buf)
			if err != nil {
				return
			}
			seen, every, dropped, delay := &r.revSeen, &r.revEvery, &r.revDropped, &r.revDelay
			if forward {
				r.client.Store(from)
				seen, every, dropped, delay = &r.fwdSeen, &r.fwdEvery, &r.fwdDropped, &r.fwdDelay
			}
			k := seen.Add(1)
			if r.blackhole.Load() || (every.Load() > 0 && k%every.Load() == 0) {
				dropped.Add(1)
				continue
			}
			pkt := append([]byte(nil), buf[:n]...)
			send := func() {
				if forward {
					_, _ = r.back.WriteToUDP(pkt, r.target)
				} else if c := r.client.Load(); c != nil {
					_, _ = r.front.WriteToUDP(pkt, c)
				}
			}
			if d := time.Duration(delay.Load()); d > 0 {
				time.AfterFunc(d, send)
			} else {
				send()
			}
		}
	}
	r.wg.Add(2)
	go pump(front, true)
	go pump(back, false)
	return r
}

func (r *relay) port() int { return r.front.LocalAddr().(*net.UDPAddr).Port }
func (r *relay) close()    { r.front.Close(); r.back.Close(); r.wg.Wait() }

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

type totals struct {
	sent, rcv, rx, late, dup int
	rttMin, rttMax, fwd, rev int // us; fwd/rev are means over answered seconds
	n                        int
}

func collect(out *outbox, leg uint32, fromTS int64) totals {
	out.mu.Lock()
	defer out.mu.Unlock()
	var t totals
	keys := map[int64]bool{}
	for _, r := range out.tx {
		if r.Leg != leg || r.TS < fromTS {
			continue
		}
		keys[r.TS] = true
		t.sent, t.rcv, t.late, t.dup = t.sent+r.Sent, t.rcv+r.Rcv, t.late+r.Late, t.dup+r.Dup
		if r.Rcv > 0 {
			if t.n == 0 || r.RTT[0] < t.rttMin {
				t.rttMin = r.RTT[0]
			}
			t.rttMax = max(t.rttMax, r.RTT[2])
			t.fwd, t.rev, t.n = t.fwd+r.Fwd, t.rev+r.Rev, t.n+1
		}
	}
	for _, r := range out.rx {
		if r.Leg == leg && keys[r.TS] {
			t.rx += r.Rx
		}
	}
	if t.n > 0 {
		t.fwd, t.rev = t.fwd/t.n, t.rev/t.n
	}
	return t
}

// TestDirectionalLoss checks that loss is counted exactly and attributed to the right direction.
func TestDirectionalLoss(t *testing.T) {
	out := &outbox{}
	refl := newReflector(out)
	rport := freeUDPPort(t)
	refl.apply([]reflCfg{{Leg: 7, Proto: "udp", Port: rport}})
	rl := newRelay(t, rport)
	defer rl.close()
	rl.fwdEvery.Store(10) // 10% forward
	rl.revEvery.Store(20) // 5% of what is left, return

	leg := startLeg(legCfg{Leg: 7, Proto: "udp", Dst: "127.0.0.1", Port: rl.port(), Size: 200, PPS: 400, TimeoutMs: 300}, out)
	time.Sleep(4500 * time.Millisecond)
	leg.close()
	time.Sleep(2500 * time.Millisecond) // the reflector reports a second once it is two seconds old

	got := collect(out, 7, 0)
	if got.sent < 1500 {
		t.Fatalf("sent only %d probes", got.sent)
	}
	// Ground truth, counted by the relay. The first probes are sent before the leg is "up" and
	// are not measured, so compare what was measured, not what was offered.
	fwdLost, revLost := got.sent-got.rx, got.rx-got.rcv
	t.Logf("sent %d, reflector saw %d, answered %d: forward loss %.2f%%, return loss %.2f%% (relay dropped %d / %d)",
		got.sent, got.rx, got.rcv, 100*float64(fwdLost)/float64(got.sent), 100*float64(revLost)/float64(got.rx),
		rl.fwdDropped.Load(), rl.revDropped.Load())
	if d := fwdLost - got.sent/10; d < -2 || d > 2 {
		t.Errorf("forward loss: measured %d, expected about %d (every 10th of %d)", fwdLost, got.sent/10, got.sent)
	}
	if d := revLost - got.rx/20; d < -2 || d > 2 {
		t.Errorf("return loss: measured %d, expected about %d (every 20th of %d)", revLost, got.rx/20, got.rx)
	}
	if got.late != 0 || got.dup != 0 {
		t.Errorf("unexpected late=%d dup=%d", got.late, got.dup)
	}
}

// TestOneWayDelay checks that a delay added to ONE direction after a clean baseline is reported
// in that direction, and that RTT has the reflector's dwell removed.
func TestOneWayDelay(t *testing.T) {
	out := &outbox{}
	refl := newReflector(out)
	rport := freeUDPPort(t)
	refl.apply([]reflCfg{{Leg: 8, Proto: "udp", Port: rport}})
	rl := newRelay(t, rport)
	defer rl.close()
	leg := startLeg(legCfg{Leg: 8, Proto: "udp", Dst: "127.0.0.1", Port: rl.port(), Size: 200, PPS: 200, TimeoutMs: 500}, out)
	time.Sleep(2500 * time.Millisecond)
	cut := nowNs()/1e9 + 1
	rl.fwdDelay.Store(int64(30 * time.Millisecond))
	time.Sleep(3500 * time.Millisecond)
	leg.close()

	base := collect(out, 8, 0)
	got := collect(out, 8, cut+1)
	t.Logf("baseline RTT min %d us; with +30 ms forward: RTT min %d us, forward %d us, return %d us",
		base.rttMin, got.rttMin, got.fwd, got.rev)
	if got.n == 0 {
		t.Fatal("no answered seconds after the delay was added")
	}
	if got.rttMin < 30000 || got.rttMin > 33000 {
		t.Errorf("RTT min with +30 ms: %d us, want 30000..33000", got.rttMin)
	}
	if got.fwd < 29500 || got.fwd > 34000 {
		t.Errorf("forward delay: %d us, want about 30000", got.fwd)
	}
	if got.rev < -500 || got.rev > 2500 {
		t.Errorf("return delay: %d us, want about 0", got.rev)
	}
	if got.sent != got.rcv {
		t.Errorf("loss on a lossless path: sent %d, answered %d", got.sent, got.rcv)
	}
}

// TestOutageDuration checks that a blackhole is reported as one interruption of the right length.
func TestOutageDuration(t *testing.T) {
	out := &outbox{}
	refl := newReflector(out)
	rport := freeUDPPort(t)
	refl.apply([]reflCfg{{Leg: 9, Proto: "udp", Port: rport}})
	rl := newRelay(t, rport)
	defer rl.close()
	const pps = 200
	leg := startLeg(legCfg{Leg: 9, Proto: "udp", Dst: "127.0.0.1", Port: rl.port(), Size: 120, PPS: pps, TimeoutMs: 300}, out)
	time.Sleep(1500 * time.Millisecond)
	const want = 730 * time.Millisecond
	rl.blackhole.Store(true)
	time.Sleep(want)
	rl.blackhole.Store(false)
	time.Sleep(1500 * time.Millisecond)
	leg.close()

	out.mu.Lock()
	defer out.mu.Unlock()
	var closed []outage
	opens := 0
	for _, e := range out.ev {
		if e.Open {
			opens++
		} else {
			closed = append(closed, e)
		}
	}
	if len(closed) != 1 || opens != 1 {
		t.Fatalf("want exactly one interruption (one open notice, one close), got %d open, %d closed: %+v", opens, len(closed), out.ev)
	}
	got := time.Duration(closed[0].End - closed[0].Start)
	t.Logf("blackhole %v measured as %v (%d probes lost at %d pps)", want, got, closed[0].Lost, pps)
	// Accurate to one packet interval either side, plus scheduling slop in the test itself.
	if diff := got - want; diff < -15*time.Millisecond || diff > 15*time.Millisecond {
		t.Errorf("measured %v, want %v within 15 ms", got, want)
	}
}

// TestTCPLeg checks a TCP leg end to end, including a reflector outage and reconnect.
func TestTCPLeg(t *testing.T) {
	out := &outbox{}
	refl := newReflector(out)
	port := freeUDPPort(t) // any free number; TCP and UDP port spaces are separate
	refl.apply([]reflCfg{{Leg: 11, Proto: "tcp", Port: port}})
	leg := startLeg(legCfg{Leg: 11, Proto: "tcp", Dst: "127.0.0.1", Port: port, Size: 512, PPS: 100, TimeoutMs: 300}, out)
	time.Sleep(1500 * time.Millisecond)
	refl.apply(nil) // listener closed and leg withdrawn: the connection must die and be counted
	time.Sleep(900 * time.Millisecond)
	refl.apply([]reflCfg{{Leg: 11, Proto: "tcp", Port: port}})
	time.Sleep(2200 * time.Millisecond)
	leg.close()

	got := collect(out, 11, 0)
	reconn := 0
	out.mu.Lock()
	for _, r := range out.tx {
		if r.Leg == 11 {
			reconn += r.Reconn
		}
	}
	events := len(out.ev)
	out.mu.Unlock()
	t.Logf("TCP: sent %d, answered %d, reconnects %d, interruption notices %d", got.sent, got.rcv, reconn, events)
	if got.sent < 350 || got.rcv < 200 {
		t.Fatalf("too little traffic: sent %d answered %d", got.sent, got.rcv)
	}
	if lost := got.sent - got.rcv; lost < 60 || lost > 200 {
		t.Errorf("lost %d messages across a 0.9 s outage at 100/s, want roughly 90..150", lost)
	}
	if reconn < 1 {
		t.Errorf("the reconnect was not counted")
	}
	if events < 2 {
		t.Errorf("the outage was not reported as an interruption")
	}
}
