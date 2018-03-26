package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
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
	}, []string{"target"})
)

func init() {
	prometheus.MustRegister(rttMetric)
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

func singleprobe(hostport, label string) error {
	conn, err := net.Dial("udp", hostport)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(
		time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	// version 4, mode 3
	req := &packet{Settings: 0x23}
	rsp := &packet{}
	if err := binary.Write(conn, binary.BigEndian, req); err != nil {
		return err
	}
	sent := time.Now()
	if err := binary.Read(conn, binary.BigEndian, rsp); err != nil {
		return err
	}
	elapsed := time.Now().Sub(sent)
	fmt.Printf("%s (%s): received in %v nanos\n", label, hostport, elapsed.Nanoseconds())
	rttMetric.With(prometheus.Labels{"target": label}).Set(elapsed.Seconds())
	return nil
}

func probe(hostport, label string) {

	loops := 0
	for {
		if loops > 0 {
			time.Sleep(30 * time.Second)
		}
		loops++
		err := singleprobe(hostport, label)
		if err != nil {
			log.Printf("%s(%s): %v", label, hostport, err)
		}
	}
}

func main() {
	flag.Parse()
	http.Handle("/metrics", promhttp.Handler())

	targets := []struct {
		label    string
		hostport string
	}{
		{"time_dns", "time.google.com:123"},
		{"time1_ipv4", "216.239.35.0:123"},
		{"time1_ipv6", "[2001:4860:4806::]:123"},
		{"time2_ipv4", "216.239.35.4:123"},
		{"time2_ipv6", "[2001:4860:4806:4::]:123"},
		{"time3_ipv4", "216.239.35.8:123"},
		{"time3_ipv6", "[2001:4860:4806:8::]:123"},
		{"time4_ipv4", "216.239.35.12:123"},
		{"time4_ipv6", "[2001:4860:4806:c::]:123"},
	}

	for _, t := range targets {
		go probe(t.hostport, t.label)
	}

	log.Fatal(http.ListenAndServe(*addr, nil))
}
