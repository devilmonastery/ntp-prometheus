package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	addr      = flag.String("listen_addr", ":12300", "The address to listen on for HTTP requests.")
	rttMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "rtt",
		Help:      "Round-trip time in seconds for NTP request/response",
	}, []string{"group", "target"})
	reachableMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "reachable",
		Help:      "If a target is reachable",
	}, []string{"group", "target"})
	dispersionMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "dispersion",
		Help:      "root dispersion",
	}, []string{"group", "target"})
)

func init() {
	prometheus.MustRegister(rttMetric)
	prometheus.MustRegister(reachableMetric)
	prometheus.MustRegister(dispersionMetric)
}

type packet struct {
	Settings       uint8
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      uint32
	RootDispersion uint32
	ReferenceID    uint32
	RefTimeSec     uint32
	RefTimeFrac    uint32
	OrigTimeSec    uint32
	OrigTimeFrac   uint32
	RxTimeSec      uint32
	RxTimeFrac     uint32
	TxTimeSec      uint32
	TxTimeFrac     uint32
}

func time16ToDuration(time16 uint32) time.Duration {
	return time.Duration(time16>>16)*time.Second + ((time.Duration(uint16(time16))*1e6)>>16)*time.Microsecond
}

func singleprobe(group, target, hostport string) error {
	// version 4, mode 3
	req := &packet{Settings: 0x23}
	rsp := &packet{}
	reachable := float64(0)
	elapsed := time.Duration(0)
	defer func() {
		reachableMetric.With(prometheus.Labels{"group": group, "target": target}).Set(reachable)
		dispersion := math.NaN()
		if reachable > 0 {
			dispersion = float64(time16ToDuration(rsp.RootDispersion).Nanoseconds()) / float64(1000)
			rttMetric.With(prometheus.Labels{"group": group, "target": target}).Set(elapsed.Seconds())
		} else {
			rttMetric.With(prometheus.Labels{"group": group, "target": target}).Set(math.NaN())
		}
		dispersionMetric.With(prometheus.Labels{"group": group, "target": target}).Set(dispersion)
		fmt.Printf("%s-%s (%s): reachable(%f) in %v nanos with dispersion %0.2f\n", group, target, hostport, reachable, elapsed.Nanoseconds(), dispersion)
	}()

	conn, err := net.Dial("udp", hostport)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(
		time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, req); err != nil {
		return err
	}
	sent := time.Now()
	if err := binary.Read(conn, binary.BigEndian, rsp); err != nil {
		return err
	}
	elapsed = time.Now().Sub(sent)
	reachable = 1

	return nil
}

func probe(group, target, hostport string) {
	for {
		err := singleprobe(group, target, hostport)
		if err != nil {
			log.Printf("%s-%s(%s): %v", group, target, hostport, err)
		}
		time.Sleep(10 * time.Second)
	}
}

func main() {
	flag.Parse()
	http.Handle("/metrics", promhttp.Handler())

	targets := []struct {
		group    string
		target   string
		hostport string
	}{
		{"google", "time_dns", "time.google.com:123"},
		{"google", "time1_ipv4", "216.239.35.0:123"},
		{"google", "time1_ipv6", "[2001:4860:4806::]:123"},
		{"google", "time2_ipv4", "216.239.35.4:123"},
		{"google", "time2_ipv6", "[2001:4860:4806:4::]:123"},
		{"google", "time3_ipv4", "216.239.35.8:123"},
		{"google", "time3_ipv6", "[2001:4860:4806:8::]:123"},
		{"google", "time4_ipv4", "216.239.35.12:123"},
		{"google", "time4_ipv6", "[2001:4860:4806:c::]:123"},

		{"apple", "time", "time.apple.com:123"},
		{"microsoft", "time", "time.windows.com:123"},

		{"nist", "time", "time.nist.gov:123"},
		{"nist", "time-a-g", "time-a-g.nist.gov:123"},
		{"nist", "time-a-b", "time-a-b.nist.gov:123"},

		{"pool", "0", "0.pool.ntp.org:123"},
		{"pool", "1", "1.pool.ntp.org:123"},
		{"pool", "2", "2.pool.ntp.org:123"},
		{"pool", "3", "3.pool.ntp.org:123"},
	}

	for _, t := range targets {
		go probe(t.group, t.target, t.hostport)
	}

	err := http.ListenAndServe(*addr, nil)
	fmt.Printf("exited: %v", err)
}
