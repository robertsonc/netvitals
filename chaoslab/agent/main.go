// chaos-agent is the ChaosLab endpoint: it generates TCP and UDP test traffic towards other
// agents, answers theirs, measures loss, delay and delay variation per direction, and reports
// to the Chaos Monkey controller.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func logf(format string, args ...any) { log.Printf(format, args...) }

func defaultStatePath() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" { // systemd StateDirectory=
		return filepath.Join(d, "agent.json")
	}
	if runtime.GOOS == "windows" {
		if d := os.Getenv("ProgramData"); d != "" {
			return filepath.Join(d, "ChaosLab", "agent.json")
		}
	}
	if os.Geteuid() == 0 {
		return "/var/lib/chaoslab/agent.json"
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "chaoslab", "agent.json")
	}
	return "agent.json"
}

func usage() {
	fmt.Fprintf(os.Stderr, `chaos-agent %s (%s/%s)

  chaos-agent run   --controller http://HOST:1666 --token JOIN-TOKEN [--name NAME]
  chaos-agent check --controller http://HOST:1666 --token JOIN-TOKEN
  chaos-agent selftest
  chaos-agent version

run       enrol with the controller (first start only) and stay running
check     verify the controller is reachable and accepts the token, then exit
selftest  measure over loopback for three seconds and print what this host can resolve

The install one-liner on the dashboard's Endpoints page does all of this for you.
`, version, runtime.GOOS, runtime.GOARCH)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	controller := fs.String("controller", os.Getenv("CHAOSLAB_CONTROLLER"), "controller URL, e.g. http://10.0.0.5:1666")
	token := fs.String("token", os.Getenv("CHAOSLAB_TOKEN"), "join token shown on the dashboard")
	name := fs.String("name", "", "name to show on the dashboard (default: hostname)")
	statePath := fs.String("state", defaultStatePath(), "where the agent keeps its identity")
	logPath := fs.String("log", "", "also append the log to this file")
	_ = fs.Parse(os.Args[2:])

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if *logPath != "" {
		if f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			log.SetOutput(f)
		} else {
			logf("cannot open log file %s: %v", *logPath, err)
		}
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println(version)
	case "selftest":
		os.Exit(selftest())
	case "run", "check":
		tuneTimer()
		st := loadState(*statePath)
		if *controller != "" {
			if st.Controller != "" && st.Controller != *controller {
				st.AgentID, st.Key = "", "" // pointed at a different controller: enrol afresh
			}
			st.Controller = *controller
		}
		if st.Controller == "" {
			fmt.Fprintln(os.Stderr, "No controller configured. Pass --controller http://HOST:1666 --token TOKEN "+
				"(copy the install command from the dashboard's Endpoints page).")
			os.Exit(2)
		}
		out := &outbox{}
		a := &agent{st: st, statePath: *statePath, token: *token, name: *name, out: out,
			client: &http.Client{Timeout: 5 * time.Second}, legs: map[uint32]*sendLeg{}}
		if os.Args[1] == "check" {
			var resp struct {
				OK    bool   `json:"ok"`
				Error string `json:"error"`
				Name  string `json:"controller"`
			}
			code, err := a.post("/api/agent/hello", map[string]string{"token": *token}, &resp, false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot reach the controller at %s: %v\n", st.Controller, err)
				os.Exit(1)
			}
			if code != 200 {
				fmt.Fprintf(os.Stderr, "Controller at %s refused the token (HTTP %d): %s\n", st.Controller, code, resp.Error)
				os.Exit(1)
			}
			fmt.Printf("OK: controller %s is reachable and accepts the token.\n", st.Controller)
			return
		}
		a.refl = newReflector(out)
		logf("chaos-agent %s starting; controller %s; clock %s; kernel rx stamps %v",
			version, st.Controller, clockSource(), kernelRxStamps)
		if err := a.run(); err != nil {
			logf("fatal: %v", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

// selftest runs a UDP and a TCP leg against this process's own reflector over loopback and
// prints the result. It needs no controller, so it is the quickest way to see what timestamp
// resolution a host actually delivers.
func selftest() int {
	tuneTimer()
	out := &outbox{}
	refl := newReflector(out)
	const port = 30299
	refl.apply([]reflCfg{{Leg: 1, Proto: "udp", Port: port}, {Leg: 2, Proto: "tcp", Port: port}})
	if p := refl.problems(); len(p) > 0 {
		fmt.Println("FAIL:", p[0])
		return 1
	}
	base := legCfg{Dst: "127.0.0.1", Port: port, Size: 200, PPS: 200, TimeoutMs: 500}
	u, t := base, base
	u.Leg, u.Proto = 1, "udp"
	t.Leg, t.Proto = 2, "tcp"
	legs := []*sendLeg{startLeg(u, out), startLeg(t, out)}

	// Smallest step the wall clock can express: the floor under every delay measurement.
	step := int64(1 << 62)
	for i := 0; i < 200000; i++ {
		a := nowNs()
		if b := nowNs(); b > a && b-a < step {
			step = b - a
		}
	}
	time.Sleep(3200 * time.Millisecond)
	for _, l := range legs {
		l.close()
	}
	fmt.Printf("chaos-agent %s on %s/%s\nclock: %s, smallest step %d ns\nkernel receive timestamps: %v\n\n",
		version, runtime.GOOS, runtime.GOARCH, clockSource(), step, kernelRxStamps)
	sent, rcv := map[uint32]int{}, map[uint32]int{}
	minRTT, maxRTT, jit, n := map[uint32]int{}, map[uint32]int{}, map[uint32]int{}, map[uint32]int{}
	for _, r := range out.tx {
		sent[r.Leg] += r.Sent
		rcv[r.Leg] += r.Rcv
		if r.Rcv > 0 {
			if n[r.Leg] == 0 || r.RTT[0] < minRTT[r.Leg] {
				minRTT[r.Leg] = r.RTT[0]
			}
			maxRTT[r.Leg] = max(maxRTT[r.Leg], r.RTT[2])
			jit[r.Leg] += r.RTTJit
			n[r.Leg]++
		}
	}
	ok := true
	for leg, proto := range map[uint32]string{1: "UDP", 2: "TCP"} {
		if n[leg] == 0 || rcv[leg] == 0 {
			fmt.Printf("%s loopback: FAIL, nothing came back (sent %d)\n", proto, sent[leg])
			ok = false
			continue
		}
		fmt.Printf("%s loopback: sent %d, answered %d, RTT min %d us / max %d us, mean jitter %d us\n",
			proto, sent[leg], rcv[leg], minRTT[leg], maxRTT[leg], jit[leg]/n[leg])
		ok = ok && rcv[leg] == sent[leg]
	}
	if !ok {
		fmt.Println("\nFAIL: loopback loss. A local firewall may be blocking UDP/TCP", port)
		return 1
	}
	fmt.Println("\nOK")
	return 0
}
