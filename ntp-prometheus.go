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
	packetTxMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "tx_time",
		Help:      "Delta between sent time at probe and recv time at server",
	}, []string{"group", "target"})
	packetRxMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "rx_time",
		Help:      "Delta between sent time at server and recv time at probe",
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
	timeOffsetMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "offset",
		Help:      "Offset from local time to server time",
	}, []string{"group", "target"})
)

const (
	NTPUTCEpochDelta = 2208988800
)

func init() {
	prometheus.MustRegister(rttMetric)
	prometheus.MustRegister(packetTxMetric)
	prometheus.MustRegister(packetRxMetric)
	prometheus.MustRegister(reachableMetric)
	prometheus.MustRegister(dispersionMetric)
	prometheus.MustRegister(timeOffsetMetric)
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
	sent := time.Now()
	recv := time.Now()

	defer func() {
		reachableMetric.With(labels).Set(reachable)
		dispersion := float64(ntpTime32ToDuration(rsp.RootDispersion).Nanoseconds()) / float64(1000)
		// We got an answer and it's plausible, report what we got.
		if reachable > 0 && dispersion > 0 {
			rttMetric.With(labels).Set(elapsed.Seconds())
			dispersionMetric.With(labels).Set(dispersion)
			offset := ((ntpTime64ToTime(rsp.RxTime).Sub(sent)) + (ntpTime64ToTime(rsp.TxTime).Sub(recv))) / 2
			timeOffsetMetric.With(labels).Set(float64(offset) / float64(1e6))
			packetTxMetric.With(labels).Set(float64(ntpTime64ToTime(rsp.RxTime).Sub(sent)))
			packetRxMetric.With(labels).Set(float64(recv.Sub(ntpTime64ToTime(rsp.TxTime))))
		} else {
			rttMetric.With(labels).Set(math.NaN())
			dispersionMetric.With(labels).Set(math.NaN())
			timeOffsetMetric.With(labels).Set(math.NaN())
			packetTxMetric.With(labels).Set(math.NaN())
			packetRxMetric.With(labels).Set(math.NaN())
		}
		fmt.Printf("%s-%s (%s): reachable(%v) in %v nanos\n", group, target, hostport, reachable > 0, elapsed.Nanoseconds())
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
	sent = time.Now()
	if err := binary.Read(conn, binary.BigEndian, rsp); err != nil {
		return err
	}
	recv = time.Now()
	elapsed = recv.Sub(sent)
	reachable = 1

	return nil
}

func probe(group, target, hostport string) {
	for {
		start := time.Now()
		err := singleprobe(group, target, hostport)
		if err != nil {
			log.Printf("%s-%s(%s): %v", group, target, hostport, err)
		}
		elapsed := time.Now().Sub(start)
		delay := 10.0 - elapsed.Seconds()
		if delay < 4 {
			delay = 4
		}
		if delay > 10 {
			delay = 10
		}
		time.Sleep(time.Duration(delay) * time.Second)
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
		{"apple", "time.asia", "time.asia.apple.com:123"},
		{"apple", "time.euro", "time.euro.apple.com:123"},

		{"microsoft", "time", "time.windows.com:123"},

		{"nist", "time-a-g", "time-a-g.nist.gov:123"},
		{"nist", "time-b-g", "time-b-g.nist.gov:123"},
		{"nist", "time-c-g", "time-c-g.nist.gov:123"},
		{"nist", "time-d-g", "time-d-g.nist.gov:123"},
		{"nist", "time-d-g", "time-d-g.nist.gov:123"},
		{"nist", "time-a-wwv", "time-a-wwv.nist.gov:123"},
		{"nist", "time-b-wwv", "time-b-wwv.nist.gov:123"},
		{"nist", "time-c-wwv", "time-c-wwv.nist.gov:123"},
		{"nist", "time-d-wwv", "time-d-wwv.nist.gov:123"},
		{"nist", "time-d-wwv", "time-d-wwv.nist.gov:123"},
		{"nist", "time-a-b", "time-a-b.nist.gov:123"},
		{"nist", "time-b-b", "time-b-b.nist.gov:123"},
		{"nist", "time-c-b", "time-c-b.nist.gov:123"},
		{"nist", "time-d-b", "time-d-b.nist.gov:123"},
		{"nist", "time-d-b", "time-d-b.nist.gov:123"},
		{"nist", "time.nist", "time.nist.gov:123"},
		{"nist", "utcnist", "utcnist.colorado.edu:123"},
		{"nist", "utcnist2", "utcnist2.colorado.edu:123"},

		{"usno", "tick.usno", "tick.usno.navy.mil:123"},
		{"usno", "tock.usno", "tock.usno.navy.mil:123"},
		{"usno", "ntp2.usno", "ntp2.usno.navy.mil:123"},
		{"usno", "tick.usnogps", "tick.usnogps.navy.mil:123"},
		{"usno", "tock.usnogps", "tock.usnogps.navy.mil:123"},

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
