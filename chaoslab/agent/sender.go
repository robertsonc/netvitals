package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// legCfg is one sender->reflector session, as handed out by the controller.
type legCfg struct {
	Leg       uint32  `json:"leg"`
	Proto     string  `json:"proto"` // udp | tcp
	Dst       string  `json:"dst"`
	Port      int     `json:"port"`
	Size      int     `json:"size"` // bytes of UDP payload, or of each TCP message
	PPS       float64 `json:"pps"`
	DSCP      int     `json:"dscp"`
	TimeoutMs int     `json:"timeout_ms"`
	MinEcho   bool    `json:"min_echo"` // reflector answers with the 44-byte header only
	Bind      string  `json:"bind"`     // local source address, empty = let routing choose
}

func (c *legCfg) validate() error {
	switch {
	case c.Proto != "udp" && c.Proto != "tcp":
		return fmt.Errorf("leg %d: protocol %q is not udp or tcp", c.Leg, c.Proto)
	case net.ParseIP(c.Dst) == nil:
		return fmt.Errorf("leg %d: destination %q is not an IP address", c.Leg, c.Dst)
	case c.Port < 1 || c.Port > 65535:
		return fmt.Errorf("leg %d: port %d out of range", c.Leg, c.Port)
	case c.Size < hdrLen || c.Size > maxPacket:
		return fmt.Errorf("leg %d: size %d outside %d..%d", c.Leg, c.Size, hdrLen, maxPacket)
	case c.PPS < 0.1 || c.PPS > 50000:
		return fmt.Errorf("leg %d: rate %.1f pps outside 0.1..50000", c.Leg, c.PPS)
	case c.DSCP < 0 || c.DSCP > 63:
		return fmt.Errorf("leg %d: DSCP %d outside 0..63", c.Leg, c.DSCP)
	case c.TimeoutMs < 50 || c.TimeoutMs > 10000:
		return fmt.Errorf("leg %d: timeout %d ms outside 50..10000", c.Leg, c.TimeoutMs)
	case c.Bind != "" && net.ParseIP(c.Bind) == nil:
		return fmt.Errorf("leg %d: bind address %q is not an IP address", c.Leg, c.Bind)
	}
	return nil
}

type sendLeg struct {
	cfg    legCfg
	st     *legStats
	out    *outbox
	stop   chan struct{}
	wg     sync.WaitGroup
	errMsg atomic.Value // string: last problem worth showing in the dashboard
	dscpOK atomic.Bool
}

func startLeg(c legCfg, out *outbox) *sendLeg {
	l := &sendLeg{cfg: c, out: out, stop: make(chan struct{})}
	l.errMsg.Store("")
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		var err error
		if c.Proto == "udp" {
			err = l.runUDP()
		} else {
			err = l.runTCP()
		}
		if err != nil {
			l.errMsg.Store(err.Error())
			logf("leg %d stopped: %v", c.Leg, err)
		}
	}()
	return l
}

func (l *sendLeg) close() {
	close(l.stop)
	l.wg.Wait()
	if l.st != nil {
		l.st.flush()
	}
}

func (l *sendLeg) stopped() bool {
	select {
	case <-l.stop:
		return true
	default:
		return false
	}
}

// pace calls send once per interval on an absolute schedule, so timer slop never accumulates.
// When the process was starved or suspended it calls missed() with the number of skipped slots
// instead of bursting to catch up.
func (l *sendLeg) pace(send func(), missed func(n int), tick func()) {
	interval := time.Duration(float64(time.Second) / l.cfg.PPS)
	start := time.Now()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	lastTick := start
	for k := int64(0); ; k++ {
		due := start.Add(time.Duration(k) * interval)
		wait := time.Until(due)
		if wait > 0 {
			timer.Reset(wait)
			select {
			case <-l.stop:
				return
			case <-timer.C:
			}
		} else if l.stopped() {
			return
		} else if -wait > 100*time.Millisecond+2*interval {
			skip := int64(-wait / interval)
			missed(int(skip))
			k += skip
		}
		send()
		if now := time.Now(); now.Sub(lastTick) >= 25*time.Millisecond {
			lastTick = now
			tick()
		}
	}
}

func (l *sendLeg) localAddr() net.IP {
	if l.cfg.Bind == "" {
		return nil
	}
	return net.ParseIP(l.cfg.Bind)
}

func (l *sendLeg) runUDP() error {
	c := l.cfg
	raddr := &net.UDPAddr{IP: net.ParseIP(c.Dst), Port: c.Port}
	var laddr *net.UDPAddr
	if ip := l.localAddr(); ip != nil {
		laddr = &net.UDPAddr{IP: ip}
	}
	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		return fmt.Errorf("cannot open a UDP socket to %s: %w", raddr, err)
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)
	kts := false
	if rc, err := conn.SyscallConn(); err == nil {
		kts = enableRxMeta(rc)
		l.dscpOK.Store(c.DSCP == 0 || setTOS(rc, c.DSCP<<2))
	}
	l.st = newLegStats(c, l.out, kts)

	l.wg.Add(1)
	go func() { // receiver
		defer l.wg.Done()
		buf, oob := make([]byte, maxPacket+64), make([]byte, 256)
		var h header
		for {
			n, oobn, _, _, err := conn.ReadMsgUDP(buf, oob)
			t4 := nowNs()
			if err != nil {
				if l.stopped() || errors.Is(err, net.ErrClosed) {
					return
				}
				// A connected UDP socket surfaces ICMP unreachable here; that is the path under
				// test misbehaving, not a reason to stop measuring.
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if ts, _, _ := parseRxMeta(oob[:oobn]); ts != 0 {
				t4 = ts
			}
			if h.parse(buf[:n]) == nil && h.Type == typeReply && h.Leg == c.Leg {
				l.st.onReply(&h, t4)
			}
		}
	}()

	pkt := make([]byte, c.Size)
	fillPadding(pkt, uint64(c.Leg)<<32|uint64(nowNs()))
	h := header{Type: typeProbe, Leg: c.Leg}
	if c.MinEcho {
		h.Flags = flagMinEcho
	}
	l.pace(func() {
		h.T1 = nowNs()
		h.Seq = l.st.register(h.T1)
		h.put(pkt)
		_, _ = conn.Write(pkt) // an error here is the network's doing; the probe times out as lost
	}, func(int) {}, func() { l.st.resolve(nowNs()) })
	l.drain()
	_ = conn.Close() // unblocks the receiver
	return nil
}

// tcpConn is one established connection of a TCP leg.
type tcpConn struct {
	c       *net.TCPConn
	dead    atomic.Bool
	lastRet uint32
}

func (l *sendLeg) runTCP() error {
	c := l.cfg
	l.st = newLegStats(c, l.out, false)
	var cur atomic.Pointer[tcpConn]

	l.wg.Add(1)
	go func() { // connector: keeps one connection up, reconnecting with backoff
		defer l.wg.Done()
		backoff, first := 250*time.Millisecond, true
		for !l.stopped() {
			tc, err := l.dialTCP()
			if err != nil {
				l.errMsg.Store(err.Error())
				select {
				case <-l.stop:
					return
				case <-time.After(backoff):
				}
				if backoff < 4*time.Second {
					backoff *= 2
				}
				continue
			}
			l.errMsg.Store("")
			backoff = 250 * time.Millisecond
			if !first {
				l.st.addTCP(0, 0, 1)
			}
			first = false
			cur.Store(tc)
			l.readTCP(tc) // returns when the connection dies or the leg stops
			cur.Store(nil)
			tc.c.Close()
		}
	}()

	frame := make([]byte, 4+c.Size)
	binary.BigEndian.PutUint32(frame, uint32(c.Size))
	pkt := frame[4:]
	fillPadding(pkt, uint64(c.Leg)<<32|uint64(nowNs()))
	h := header{Type: typeProbe, Leg: c.Leg}
	if c.MinEcho {
		h.Flags = flagMinEcho
	}
	timeout := time.Duration(c.TimeoutMs) * time.Millisecond
	interval := int64(float64(time.Second) / c.PPS)
	lastInfo := time.Now()
	l.pace(func() {
		h.T1 = nowNs()
		h.Seq = l.st.register(h.T1)
		tc := cur.Load()
		if tc == nil || tc.dead.Load() {
			return // no connection: the message could not be delivered and times out as lost
		}
		h.put(pkt)
		_ = tc.c.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := tc.c.Write(frame); err != nil {
			tc.dead.Store(true)
			tc.c.Close()
		}
	}, func(n int) {
		// A write that blocked on a stalled connection made us miss slots. The application
		// wanted to send them, so they count as undelivered rather than vanishing.
		if n > 5*int(c.PPS)+1 {
			n = 5*int(c.PPS) + 1
		}
		now := nowNs()
		for i := n; i > 0; i-- {
			l.st.register(now - int64(i)*interval)
		}
	}, func() {
		l.st.resolve(nowNs())
		if time.Since(lastInfo) < time.Second {
			return
		}
		lastInfo = time.Now()
		if tc := cur.Load(); tc != nil {
			if rc, err := tc.c.SyscallConn(); err == nil {
				if ret, srtt, ok := tcpInfo(rc); ok {
					l.st.addTCP(int(ret-tc.lastRet), int(srtt), 0)
					tc.lastRet = ret
				} else {
					l.st.addTCP(-1, 0, 0)
				}
			}
		}
	})
	l.drain()
	if tc := cur.Load(); tc != nil {
		tc.c.Close()
	}
	return nil
}

// drain waits, after the last probe, for answers still in flight: a leg that is stopped must not
// book the probes it had on the wire as lost. Bounded by the leg's timeout.
func (l *sendLeg) drain() {
	deadline := time.Now().Add(time.Duration(l.cfg.TimeoutMs) * time.Millisecond)
	for time.Now().Before(deadline) {
		l.st.resolve(nowNs())
		if l.st.settled() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (l *sendLeg) dialTCP() (*tcpConn, error) {
	c := l.cfg
	d := net.Dialer{Timeout: 3 * time.Second}
	if ip := l.localAddr(); ip != nil {
		d.LocalAddr = &net.TCPAddr{IP: ip}
	}
	conn, err := d.Dial("tcp4", net.JoinHostPort(c.Dst, fmt.Sprint(c.Port)))
	if err != nil {
		return nil, fmt.Errorf("cannot connect to %s:%d: %w", c.Dst, c.Port, err)
	}
	tc := conn.(*net.TCPConn)
	_ = tc.SetNoDelay(true)
	if rc, err := tc.SyscallConn(); err == nil {
		l.dscpOK.Store(c.DSCP == 0 || setTOS(rc, c.DSCP<<2))
	}
	hello := make([]byte, 4+hdrLen)
	binary.BigEndian.PutUint32(hello, hdrLen)
	(&header{Type: typeHello, Leg: c.Leg}).put(hello[4:])
	_ = tc.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := tc.Write(hello); err != nil {
		tc.Close()
		return nil, fmt.Errorf("connected to %s:%d but the hello failed: %w", c.Dst, c.Port, err)
	}
	return &tcpConn{c: tc}, nil
}

func (l *sendLeg) readTCP(tc *tcpConn) {
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() { // closing the socket is the only way to interrupt a blocked read
		select {
		case <-l.stop:
			tc.c.Close()
		case <-stopWatch:
		}
	}()
	r := bufio.NewReaderSize(tc.c, 64<<10)
	buf := make([]byte, maxPacket)
	var h header
	for {
		n, err := readFrame(r, buf)
		t4 := nowNs()
		if err != nil {
			tc.dead.Store(true)
			return
		}
		if h.parse(buf[:n]) == nil && h.Type == typeReply && h.Leg == l.cfg.Leg {
			l.st.onReply(&h, t4)
		}
	}
}

// readFrame reads one length-prefixed message into buf and returns its length.
func readFrame(r io.Reader, buf []byte) (int, error) {
	var lb [4]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint32(lb[:]))
	if n < hdrLen || n > len(buf) {
		return 0, errBadPacket
	}
	_, err := io.ReadFull(r, buf[:n])
	return n, err
}
