package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// reflCfg tells this agent which legs it answers. Anything else is dropped unanswered, so the
// reflector cannot be used by a host the controller did not pair it with.
type reflCfg struct {
	Leg   uint32 `json:"leg"`
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	DSCP  int    `json:"dscp"`
}

type reflLeg struct {
	mu      sync.Mutex
	cfg     reflCfg
	tosCtl  []byte
	seen    [1024]uint32 // seq+1 per slot: duplicate detection over the last 1024 probes
	hi      uint32
	have    bool
	skew    int64 // sender clock minus local clock, as of the last probe (includes path delay)
	emitted int64 // last sender-clock second already reported
	buckets map[int64]*rxRec
}

// record books one received probe. local is this host's receive time.
func (l *reflLeg) record(h *header, size int, local int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sec := h.T1 / 1e9
	if !l.have {
		l.emitted = sec - 1
	}
	l.skew = h.T1 - local
	if sec <= l.emitted {
		return // its second was already reported; the sender's own late/lost accounting covers it
	}
	b := l.buckets[sec]
	if b == nil {
		b = &rxRec{Leg: l.cfg.Leg, TS: sec}
		l.buckets[sec] = b
	}
	slot := &l.seen[h.Seq&1023]
	if *slot == h.Seq+1 {
		b.Dup++
		return
	}
	*slot = h.Seq + 1
	b.Rx++
	b.Bytes += int64(size)
	if l.have && int32(h.Seq-l.hi) < 0 {
		b.Reord++
	} else {
		l.hi = h.Seq
	}
	l.have = true
}

// emit reports every sender-clock second that is at least two seconds old, INCLUDING seconds in
// which nothing arrived: an explicit zero is what lets the controller call an outage
// "forward loss" while it is still happening.
func (l *reflLeg) emit(local int64, out *outbox) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.have {
		return
	}
	upTo := (local+l.skew)/1e9 - 2
	if upTo-l.emitted > 300 {
		l.emitted = upTo - 300 // long gap (suspend, clock step): do not flood
	}
	for sec := l.emitted + 1; sec <= upTo; sec++ {
		if b := l.buckets[sec]; b != nil {
			out.addRx(*b)
			delete(l.buckets, sec)
		} else {
			out.addRx(rxRec{Leg: l.cfg.Leg, TS: sec})
		}
		l.emitted = sec
	}
}

type listenKey struct {
	proto string
	port  int
}

type reflector struct {
	mu      sync.RWMutex
	legs    map[uint32]*reflLeg
	closers map[listenKey]func()
	errs    map[listenKey]string
	out     *outbox
}

func newReflector(out *outbox) *reflector {
	r := &reflector{legs: map[uint32]*reflLeg{}, closers: map[listenKey]func(){}, errs: map[listenKey]string{}, out: out}
	go func() {
		for range time.Tick(time.Second) {
			now := nowNs()
			r.mu.RLock()
			for _, l := range r.legs {
				l.emit(now, out)
			}
			r.mu.RUnlock()
		}
	}()
	return r
}

func (r *reflector) leg(id uint32, proto string) *reflLeg {
	r.mu.RLock()
	l := r.legs[id]
	r.mu.RUnlock()
	if l == nil || l.cfg.Proto != proto {
		return nil
	}
	return l
}

// apply replaces the set of answered legs and opens or closes listeners to match.
func (r *reflector) apply(cfgs []reflCfg) {
	r.mu.Lock()
	defer r.mu.Unlock()
	want := map[listenKey]bool{}
	legs := map[uint32]*reflLeg{}
	for _, c := range cfgs {
		if (c.Proto != "udp" && c.Proto != "tcp") || c.Port < 1 || c.Port > 65535 || c.DSCP < 0 || c.DSCP > 63 {
			continue
		}
		want[listenKey{c.Proto, c.Port}] = true
		if old := r.legs[c.Leg]; old != nil && old.cfg == c {
			legs[c.Leg] = old
			continue
		}
		l := &reflLeg{cfg: c, buckets: map[int64]*rxRec{}}
		if c.DSCP != 0 {
			l.tosCtl = tosControl(uint8(c.DSCP << 2))
		}
		legs[c.Leg] = l
	}
	r.legs = legs
	for k, stop := range r.closers {
		if !want[k] {
			stop()
			delete(r.closers, k)
		}
	}
	for k := range want {
		if r.closers[k] != nil {
			continue
		}
		stop, err := r.listen(k)
		if err != nil {
			r.errs[k] = err.Error()
			logf("reflector: %v", err)
			continue
		}
		delete(r.errs, k)
		r.closers[k] = stop
	}
}

func (r *reflector) problems() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for _, e := range r.errs {
		out = append(out, e)
	}
	return out
}

func (r *reflector) listen(k listenKey) (func(), error) {
	if k.proto == "udp" {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: k.port})
		if err != nil {
			return nil, fmt.Errorf("cannot listen on UDP %d: %w", k.port, err)
		}
		_ = conn.SetReadBuffer(4 << 20)
		_ = conn.SetWriteBuffer(4 << 20)
		go r.serveUDP(conn)
		return func() { conn.Close() }, nil
	}
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{Port: k.port})
	if err != nil {
		return nil, fmt.Errorf("cannot listen on TCP %d: %w", k.port, err)
	}
	go func() {
		for {
			conn, err := ln.AcceptTCP()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			go r.serveTCP(conn)
		}
	}()
	return func() { ln.Close() }, nil
}

func (r *reflector) serveUDP(conn *net.UDPConn) {
	kts := false
	if rc, err := conn.SyscallConn(); err == nil {
		kts = enableRxMeta(rc)
	}
	buf, oob := make([]byte, maxPacket+64), make([]byte, 256)
	var h header
	for {
		n, oobn, _, from, err := conn.ReadMsgUDPAddrPort(buf, oob)
		local := nowNs()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(5 * time.Millisecond) // e.g. ICMP-induced errors on Windows
			continue
		}
		if h.parse(buf[:n]) != nil || h.Type != typeProbe {
			continue
		}
		l := r.leg(h.Leg, "udp")
		if l == nil {
			continue
		}
		t2 := local
		h.Flags &= flagMinEcho
		ts, ttl, tos := parseRxMeta(oob[:oobn])
		if kts && ts != 0 {
			t2 = ts
			h.Flags |= flagKernelTS
		}
		l.record(&h, n, local)
		out := n
		if h.Flags&flagMinEcho != 0 {
			out = hdrLen
		}
		h.Type, h.T2, h.RxTTL, h.RxTOS = typeReply, t2, ttl, tos
		h.T3 = nowNs()
		h.put(buf)
		_, _, _ = conn.WriteMsgUDPAddrPort(buf[:out], l.tosCtl, netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
	}
}

func (r *reflector) serveTCP(conn *net.TCPConn) {
	defer conn.Close()
	_ = conn.SetNoDelay(true)
	rd := bufio.NewReaderSize(conn, 64<<10)
	buf := make([]byte, 4+maxPacket)
	msg := buf[4:]
	var h header
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := readFrame(rd, msg)
	if err != nil || h.parse(msg[:n]) != nil || h.Type != typeHello {
		return
	}
	l := r.leg(h.Leg, "tcp")
	if l == nil {
		return
	}
	if rc, err := conn.SyscallConn(); err == nil && l.cfg.DSCP != 0 {
		setTOS(rc, l.cfg.DSCP<<2)
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := readFrame(rd, msg)
		t2 := nowNs()
		if err != nil || h.parse(msg[:n]) != nil || h.Type != typeProbe || h.Leg != l.cfg.Leg {
			return
		}
		if r.leg(h.Leg, "tcp") != l {
			return // the controller withdrew this leg
		}
		l.record(&h, n, t2)
		out := n
		if h.Flags&flagMinEcho != 0 {
			out = hdrLen
		}
		h.Type, h.Flags, h.T2 = typeReply, h.Flags&flagMinEcho, t2
		h.T3 = nowNs()
		h.put(msg)
		binary.BigEndian.PutUint32(buf, uint32(out))
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(buf[:4+out]); err != nil {
			return
		}
	}
}
