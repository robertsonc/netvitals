package main

import (
	"sort"
	"sync"
)

// Records uploaded to the controller. Times are this host's wall clock; the controller converts
// with the per-agent offset it learns from the sync exchange.

// txRec is one second of one leg, keyed by the second the probes were SENT in.
// It is emitted only once every probe sent in that second has been resolved (answered or timed out).
type txRec struct {
	Leg    uint32 `json:"leg"`
	TS     int64  `json:"ts"`    // sender-clock second
	Sent   int    `json:"sent"`  // probes sent
	Rcv    int    `json:"rcv"`   // answered within the timeout
	Late   int    `json:"late"`  // answers that arrived after the timeout (counted when they arrive)
	Dup    int    `json:"dup"`   // duplicate answers
	Reord  int    `json:"reord"` // answers that arrived behind a later sequence number
	Bytes  int64  `json:"bytes"`
	RTT    [6]int `json:"rtt"`    // us: min, mean, max, p50, p95, p99; reflector dwell removed
	Fwd    int    `json:"fwd"`    // us: mean one-way delay sender->reflector (estimate, see offsetEst)
	Rev    int    `json:"rev"`    // us: mean one-way delay reflector->sender (estimate)
	FwdJit int    `json:"fj"`     // us: mean |delay variation| between consecutive probes, forward
	RevJit int    `json:"rj"`     // us: same, return direction
	RTTJit int    `json:"tj"`     // us: same, round trip
	Retx   int    `json:"retx"`   // TCP only: segments the kernel retransmitted this second (-1 = unknown)
	SRTT   int    `json:"srtt"`   // TCP only: kernel smoothed RTT, us
	Reconn int    `json:"reconn"` // TCP only: reconnects this second
	TTL    int    `json:"ttl"`    // IP TTL the probes arrived with at the reflector (0 = unknown)
	KTS    int    `json:"kts"`    // bit0: reflector used kernel rx stamps, bit1: sender did
}

// rxRec is what the reflector saw for the same sender-clock second. Joined with txRec by the
// controller it splits loss by direction: forward = sent - rx, return = rx - rcv.
type rxRec struct {
	Leg   uint32 `json:"leg"`
	TS    int64  `json:"ts"`
	Rx    int    `json:"rx"`
	Dup   int    `json:"dup"`
	Reord int    `json:"reord"`
	Bytes int64  `json:"bytes"`
}

// outage is a run of consecutive unanswered probes: the data-plane interruption a failover causes.
// Start is the send time of the first lost probe, End the send time of the first probe answered
// afterwards, so the duration is accurate to one packet interval.
type outage struct {
	Leg   uint32 `json:"leg"`
	Start int64  `json:"start"` // ns
	End   int64  `json:"end"`   // ns, 0 while still open
	Lost  int    `json:"lost"`
	Open  bool   `json:"open"`
}

type outbox struct {
	mu sync.Mutex
	tx []txRec
	rx []rxRec
	ev []outage
}

const outboxCap = 40000 // records kept while the controller is unreachable; oldest dropped first

func (o *outbox) addTx(r txRec) {
	o.mu.Lock()
	if len(o.tx) >= outboxCap {
		o.tx = o.tx[len(o.tx)/10:]
	}
	o.tx = append(o.tx, r)
	o.mu.Unlock()
}

func (o *outbox) addRx(r rxRec) {
	o.mu.Lock()
	if len(o.rx) >= outboxCap {
		o.rx = o.rx[len(o.rx)/10:]
	}
	o.rx = append(o.rx, r)
	o.mu.Unlock()
}

func (o *outbox) addEv(e outage) {
	o.mu.Lock()
	if len(o.ev) >= outboxCap {
		o.ev = o.ev[len(o.ev)/10:]
	}
	o.ev = append(o.ev, e)
	o.mu.Unlock()
}

// offsetEst estimates the reflector's clock offset relative to this host so that one-way delay
// can be shown without synchronised clocks.
//
// Each exchange yields theta = ((t2-t1) - (t4-t3)) / 2, which equals the true offset only when
// the path delay is the same in both directions. The estimate is therefore taken from the
// lowest-RTT exchanges, where queueing is least likely to be lopsided. It is held for five
// minutes so that an impairment added to ONE direction shows up in that direction instead of
// being averaged across both, and it follows clock drift by preferring the most recent
// exchange that is as good as the best one.
//
// What is exact regardless: RTT, loss per direction, and delay VARIATION per direction.
// What is an estimate: the absolute split of RTT into forward and return delay.
type offsetEst struct {
	slot   [30]struct{ idx, rtt, theta int64 }
	cached int64
	at     int64
}

const offsetSlotNs = 10e9

func (e *offsetEst) add(now, rtt, theta int64) {
	idx := now/offsetSlotNs + 1 // +1 so that the zero value means "empty"
	s := &e.slot[idx%int64(len(e.slot))]
	if s.idx != idx || rtt < s.rtt {
		s.idx, s.rtt, s.theta = idx, rtt, theta
		if e.at == 0 {
			e.cached, e.at = theta, now
		}
	}
}

func (e *offsetEst) theta(now int64) int64 {
	if now-e.at < 1e9 && e.at != 0 {
		return e.cached
	}
	cur := now/offsetSlotNs + 1
	best := int64(-1)
	for _, s := range e.slot {
		if s.idx != 0 && cur-s.idx < int64(len(e.slot)) && (best < 0 || s.rtt < best) {
			best = s.rtt
		}
	}
	if best < 0 {
		return e.cached
	}
	margin := best / 20
	if margin < 200e3 {
		margin = 200e3
	}
	newest := int64(0)
	for _, s := range e.slot {
		if s.idx != 0 && cur-s.idx < int64(len(e.slot)) && s.rtt <= best+margin && s.idx > newest {
			newest, e.cached = s.idx, s.theta
		}
	}
	e.at = now
	return e.cached
}

const (
	stEmpty = iota
	stPending
	stReplied
	stLost
)

type pend struct {
	seq   uint32
	t1    int64
	state uint8
}

type bucket struct {
	sent, lost     int
	bytes          int64
	rtts           []int32 // us
	fwd, rev       int64   // ns sums
	fj, rj, tj     int64   // ns sums of |variation|
	jn             int
	ttl, kts       int
	late, dup, reo int
}

// legStats is the sender-side accounting for one leg. Probes are registered before they are sent
// and resolved strictly in sequence order, so every probe ends up as exactly one of answered or
// lost, and trailing loss is seen even when nothing ever comes back.
type legStats struct {
	mu      sync.Mutex
	leg     uint32
	size    int
	timeout int64
	minRun  int // consecutive losses that make an outage
	out     *outbox

	ring []pend
	mask uint32
	next uint32 // next sequence number to assign
	cur  uint32 // first unresolved sequence number
	up   bool   // the reflector has answered at least once; nothing is counted before that

	buckets map[int64]*bucket
	lastSec int64

	hi                        uint32
	haveHi                    bool
	prevFwd, prevRev, prevRTT int64
	havePrev                  bool
	est                       offsetEst

	run      int
	runStart int64
	open     bool

	retx, srtt, reconn int // TCP: accumulated since the last emitted bucket
	tcp                bool
	senderKTS          bool
}

func newLegStats(c legCfg, out *outbox, senderKTS bool) *legStats {
	timeout := int64(c.TimeoutMs) * 1e6
	n := 1024
	for want := int(c.PPS*float64(c.TimeoutMs)/1000*4) + 64; n < want && n < 1<<21; {
		n <<= 1
	}
	minRun := int(c.PPS*0.05 + 0.999)
	if minRun < 3 {
		minRun = 3
	}
	return &legStats{leg: c.Leg, size: c.Size, timeout: timeout, minRun: minRun, out: out,
		ring: make([]pend, n), mask: uint32(n - 1), buckets: map[int64]*bucket{},
		tcp: c.Proto == "tcp", senderKTS: senderKTS}
}

// register records a probe about to be sent and returns its sequence number. It must run before
// the write: a reply can beat bookkeeping done afterwards and would then be discarded as unknown.
func (s *legStats) register(t1 int64) uint32 {
	s.mu.Lock()
	if s.next-s.cur >= uint32(len(s.ring)) {
		s.resolveLocked(t1 + s.timeout + 1) // ring full: the resolver fell behind, settle everything
	}
	seq := s.next
	s.next++
	s.ring[seq&s.mask] = pend{seq: seq, t1: t1, state: stPending}
	s.mu.Unlock()
	return seq
}

func (s *legStats) bucket(t1 int64) *bucket {
	sec := t1 / 1e9
	b := s.buckets[sec]
	if b == nil {
		b = &bucket{}
		s.buckets[sec] = b
	}
	return b
}

// onReply accounts one answer. t4 is this host's receive time for it.
func (s *legStats) onReply(h *header, t4 int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &s.ring[h.Seq&s.mask]
	if p.state == stEmpty || p.seq != h.Seq || p.t1 != h.T1 {
		return // not ours, or from before a restart
	}
	if !s.up {
		// First answer ever: measurement starts here. Probes sent while the far end was still
		// learning about this leg are not held against the path.
		s.up, s.cur, s.lastSec = true, h.Seq, p.t1/1e9
	}
	if int32(h.Seq-s.cur) < 0 { // already resolved
		if p.state == stLost {
			s.latest().late++
		} else {
			s.latest().dup++
		}
		return
	}
	b := s.bucket(p.t1)
	switch p.state {
	case stReplied:
		b.dup++
		return
	case stLost:
		b.late++
		return
	}
	if t4-p.t1 > s.timeout {
		p.state = stLost // answered, but too late to count; the resolver books the loss
		b.late++
		return
	}
	p.state = stReplied

	dwell := h.T3 - h.T2
	if dwell < 0 || dwell > 1e9 {
		dwell = 0
	}
	rtt := t4 - p.t1 - dwell
	if rtt < 0 {
		rtt = 0 // a clock step on this host mid-flight
	}
	fwdRaw, revRaw := h.T2-p.t1, t4-h.T3
	s.est.add(t4, rtt, (fwdRaw-revRaw)/2)
	theta := s.est.theta(t4)
	b.rtts = append(b.rtts, int32(rtt/1000))
	b.fwd += fwdRaw - theta
	b.rev += revRaw + theta
	if s.havePrev {
		b.fj += abs64(fwdRaw - s.prevFwd)
		b.rj += abs64(revRaw - s.prevRev)
		b.tj += abs64(rtt - s.prevRTT)
		b.jn++
	}
	s.prevFwd, s.prevRev, s.prevRTT, s.havePrev = fwdRaw, revRaw, rtt, true
	if s.haveHi && int32(h.Seq-s.hi) < 0 {
		b.reo++
	} else {
		s.hi, s.haveHi = h.Seq, true
	}
	if h.RxTTL != 0 {
		b.ttl = int(h.RxTTL)
	}
	if h.Flags&flagKernelTS != 0 {
		b.kts |= 1
	}
}

// latest is the newest open bucket, used for late and duplicate answers whose own second has
// already been emitted.
func (s *legStats) latest() *bucket {
	if b := s.buckets[s.lastSec]; b != nil {
		return b
	}
	return s.bucket(s.lastSec * 1e9)
}

func (s *legStats) resolve(now int64) {
	s.mu.Lock()
	s.resolveLocked(now)
	s.mu.Unlock()
}

func (s *legStats) resolveLocked(now int64) {
	if !s.up {
		return
	}
	for s.cur != s.next {
		p := &s.ring[s.cur&s.mask]
		if p.state == stPending {
			if now-p.t1 <= s.timeout {
				break
			}
			p.state = stLost
		}
		if sec := p.t1 / 1e9; sec > s.lastSec {
			s.emitBelow(sec)
			s.lastSec = sec
		}
		b := s.bucket(p.t1)
		b.sent++
		b.bytes += int64(s.size)
		if p.state == stLost {
			b.lost++
			if s.run == 0 {
				s.runStart = p.t1
			}
			s.run++
			if !s.open && s.run >= s.minRun {
				s.open = true
				s.out.addEv(outage{Leg: s.leg, Start: s.runStart, Lost: s.run, Open: true})
			}
		} else {
			if s.open {
				s.out.addEv(outage{Leg: s.leg, Start: s.runStart, End: p.t1, Lost: s.run})
				s.open = false
			}
			s.run = 0
		}
		s.cur++
	}
}

// settled reports whether every probe sent so far has been answered or timed out.
func (s *legStats) settled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.up || s.cur == s.next
}

// flush settles everything outstanding as lost and emits it; used when the leg stops.
func (s *legStats) flush() {
	s.mu.Lock()
	if s.up {
		s.resolveLocked(int64(1) << 62)
		s.emitBelow(int64(1) << 62)
		if s.open {
			s.out.addEv(outage{Leg: s.leg, Start: s.runStart, End: nowNs(), Lost: s.run})
			s.open = false
		}
	}
	s.mu.Unlock()
}

func (s *legStats) addTCP(retx, srtt, reconn int) {
	s.mu.Lock()
	if retx < 0 || s.retx < 0 {
		s.retx = -1
	} else {
		s.retx += retx
	}
	if srtt > 0 {
		s.srtt = srtt
	}
	s.reconn += reconn
	s.mu.Unlock()
}

func (s *legStats) emitBelow(sec int64) {
	keys := make([]int64, 0, len(s.buckets))
	for k := range s.buckets {
		if k < sec {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		b := s.buckets[k]
		delete(s.buckets, k)
		if b.sent == 0 && b.late == 0 && b.dup == 0 {
			continue
		}
		r := txRec{Leg: s.leg, TS: k, Sent: b.sent, Rcv: len(b.rtts), Late: b.late, Dup: b.dup, Reord: b.reo,
			Bytes: b.bytes, TTL: b.ttl, KTS: b.kts}
		if s.senderKTS {
			r.KTS |= 2
		}
		if n := len(b.rtts); n > 0 {
			sort.Slice(b.rtts, func(i, j int) bool { return b.rtts[i] < b.rtts[j] })
			var sum int64
			for _, v := range b.rtts {
				sum += int64(v)
			}
			r.RTT = [6]int{int(b.rtts[0]), int(sum / int64(n)), int(b.rtts[n-1]),
				int(pct(b.rtts, 50)), int(pct(b.rtts, 95)), int(pct(b.rtts, 99))}
			r.Fwd, r.Rev = int(b.fwd/int64(n)/1000), int(b.rev/int64(n)/1000)
		}
		if b.jn > 0 {
			r.FwdJit, r.RevJit, r.RTTJit = int(b.fj/int64(b.jn)/1000), int(b.rj/int64(b.jn)/1000), int(b.tj/int64(b.jn)/1000)
		}
		if s.tcp {
			r.Retx, r.SRTT, r.Reconn = s.retx, s.srtt, s.reconn
			s.retx, s.reconn = 0, 0
		}
		s.out.addTx(r)
	}
}

// pct is the nearest-rank percentile of an ascending slice.
func pct(sorted []int32, p int) int32 {
	i := (len(sorted)*p + 99) / 100
	if i < 1 {
		i = 1
	}
	return sorted[i-1]
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
