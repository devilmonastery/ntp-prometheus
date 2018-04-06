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
	xmtTimeMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "xmt",
		Help:      "Time at server (transmit timestamp) in seconds since epoch",
	}, []string{"group", "target"})
)

const (
	NTPUTCEpochDelta = 2208988800
)

func init() {
	prometheus.MustRegister(rttMetric)
	prometheus.MustRegister(reachableMetric)
	prometheus.MustRegister(dispersionMetric)
	prometheus.MustRegister(xmtTimeMetric)
}

type packet struct {
	Settings       uint8
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      uint32
	RootDispersion uint32
	ReferenceID    uint32
	RefTime        uint64
	OrigTime       uint64
	RxTime         uint64
	TxTime         uint64
}

func ntpTime32ToDuration(ntpTime32 uint32) time.Duration {
	return time.Duration(ntpTime32>>16)*time.Second + ((time.Duration(uint16(ntpTime32))*1e6)>>16)*time.Microsecond
}

func ntpTime64ToTime(ntpTime64 uint64) time.Time {
	sec := int64(ntpTime64>>32) - NTPUTCEpochDelta
	nsec := int64((uint64(uint32(ntpTime64)) * 1e9) >> 32)
	return time.Unix(sec, nsec)
}

func singleprobe(group, target, hostport string) error {
	reachable := float64(0)
	elapsed := time.Duration(0)
	labels := prometheus.Labels{"group": group, "target": target}
	rsp := &packet{}

	defer func() {
		reachableMetric.With(labels).Set(reachable)
		dispersion := float64(ntpTime32ToDuration(rsp.RootDispersion).Nanoseconds()) / float64(1000)
		xmt := float64(ntpTime64ToTime(rsp.TxTime).UnixNano()) / float64(1e9)
		// We got an answer and it's plausible, report what we got.
		if reachable > 0 && dispersion > 0 {
			rttMetric.With(labels).Set(elapsed.Seconds())
			dispersionMetric.With(labels).Set(dispersion)
			xmtTimeMetric.With(labels).Set(xmt)
		} else {
			rttMetric.With(labels).Set(math.NaN())
			dispersionMetric.With(labels).Set(math.NaN())
			xmtTimeMetric.With(labels).Set(math.NaN())
		}
		fmt.Printf("%s-%s (%s): reachable(%v) in %v nanos with dispersion %0.2f and xmt %0.2f\n", group, target, hostport, reachable > 0, elapsed.Nanoseconds(), dispersion, xmt)
	}()

	// version 4, mode 3
	req := &packet{Settings: 0x23}
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
