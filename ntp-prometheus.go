package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	defaultAddr     = ":12300"
	defaultInterval = float64(10) // seconds
	minInterval     = float64(5)  //seconds

	config = flag.String("config", "", "path to the config file")

	// Prometheus metrics
	rttMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "rtt_seconds",
		Help:      "Round-trip time in seconds for NTP request/response",
	}, []string{"group", "target", "addrtype", "addr"})
	packetTxMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "tx_time_seconds",
		Help:      "Delta between sent time at probe and recv time at server",
	}, []string{"group", "target", "addrtype", "addr"})
	packetRxMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "rx_time_seconds",
		Help:      "Delta between sent time at server and recv time at probe",
	}, []string{"group", "target", "addrtype", "addr"})
	reachableMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "reachable",
		Help:      "If a target is reachable",
	}, []string{"group", "target", "addrtype", "addr"})
	dispersionMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "dispersion",
		Help:      "root dispersion",
	}, []string{"group", "target", "addrtype", "addr"})
	dispersionSecondsMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "dispersion_seconds",
		Help:      "root dispersion",
	}, []string{"group", "target", "addrtype", "addr"})
	timeOffsetMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ntp",
		Subsystem: "probe",
		Name:      "offset_seconds",
		Help:      "Offset from local time to server time",
	}, []string{"group", "target", "addrtype", "addr"})
)

const (
	ntpUTCEpochDelta = 2208988800
)

func init() {
	prometheus.MustRegister(rttMetric)
	prometheus.MustRegister(packetTxMetric)
	prometheus.MustRegister(packetRxMetric)
	prometheus.MustRegister(reachableMetric)
	prometheus.MustRegister(dispersionMetric)
	prometheus.MustRegister(dispersionSecondsMetric)
	prometheus.MustRegister(timeOffsetMetric)
}

// Config is the external config.
type Config struct {
	Addr     string   `yaml:"addr"`
	Interval float64  `yaml:"interval"`
	Targets  []Target `yaml:"targets"`
}

// Target is contained in a Config.
type Target struct {
	Name     string  `yaml:"name"`
	Group    string  `yaml:"group"`
	Hostport string  `yaml:"hostport"`
	Interval float64 `yaml:"interval"`
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
	sec := int64(ntpTime64>>32) - ntpUTCEpochDelta
	nsec := int64((uint64(uint32(ntpTime64)) * 1e9) >> 32)
	return time.Unix(sec, nsec)
}

func singleprobe(conf Target, conn net.Conn) error {
	reachable := float64(0)
	elapsed := time.Duration(0)
	raddr, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	addrtype := "ipv4"
	if strings.Contains(raddr, ":") {
		addrtype = "ipv6"
	}
	labels := prometheus.Labels{
		"group":    conf.Group,
		"target":   conf.Name,
		"addr":     raddr,
		"addrtype": addrtype,
	}

	// version 4, mode 3
	req := &packet{Settings: 0x23}
	if err := conn.SetDeadline(
		time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	sent := time.Now()
	recv := time.Now()
	rsp := &packet{}

	defer func() {
		reachableMetric.With(labels).Set(reachable)
		dispersionNS := float64(ntpTime32ToDuration(rsp.RootDispersion).Nanoseconds())
		// We got an answer and it's plausible, report what we got.
		if reachable > 0 && dispersionNS > 0 {
			// rtt as observed from the probe alone.
			rtt := elapsed.Seconds()
			rttMetric.With(labels).Set(rtt)
			// Dispersion, in microseconds unfortunately (old metric).
			dispersionMetric.With(labels).Set(dispersionNS / float64(1000))
			// Dispersion, in seconds (new metric).
			dispersionSecondsMetric.With(labels).Set(dispersionNS / float64(10e9))
			// Tx and Rx time, using reported time in the response.
			// Tx: time from client -> server
			tx := float64(ntpTime64ToTime(rsp.RxTime).Sub(sent).Seconds())
			packetTxMetric.With(labels).Set(tx)
			// Rx: time from server -> client
			rx := float64(recv.Sub(ntpTime64ToTime(rsp.TxTime)).Seconds())
			packetRxMetric.With(labels).Set(rx)
			// Offset from local clock time, using reported time in response.
			offset := (rx + tx) / 2
			timeOffsetMetric.With(labels).Set(offset)
		} else {
			rttMetric.With(labels).Set(math.NaN())
			dispersionMetric.With(labels).Set(math.NaN())
			dispersionSecondsMetric.With(labels).Set(math.NaN())
			timeOffsetMetric.With(labels).Set(math.NaN())
			packetTxMetric.With(labels).Set(math.NaN())
			packetRxMetric.With(labels).Set(math.NaN())
		}
	}()

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

func probe(conf Target) {
	for {
		conn, err := net.Dial("udp", conf.Hostport)
		start := time.Now()
		if err == nil {
			err = singleprobe(conf, conn)
			if err != nil {
				log.Printf("error: %s-%s(%s): %v", conf.Group, conf.Name, conf.Hostport, err)
			}
		} else {
			log.Printf("error: %s-%s(%s): %v", conf.Group, conf.Name, conf.Hostport, err)
		}
		elapsed := time.Now().Sub(start)
		delay := float64(conf.Interval) - elapsed.Seconds()
		if delay < minInterval {
			delay = minInterval
		}
		delay = math.Min(delay, conf.Interval)
		time.Sleep(time.Duration(delay) * time.Second)
	}
}

func main() {
	flag.Parse()
	http.Handle("/metrics", promhttp.Handler())

	configBytes, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatalf("could not read config %q: %v", *config, err)
	}

	conf := &Config{}
	err = yaml.Unmarshal(configBytes, &conf)
	if err != nil {
		log.Fatalf("could not read config: %v", err)
	}
	log.Printf("read config\n")

	interval := defaultInterval
	if conf.Interval > 0 {
		interval = conf.Interval
	}

	for _, t := range conf.Targets {
		if t.Hostport == "" {
			t.Hostport = fmt.Sprintf("%s:123", t.Name)
		}
		if t.Interval <= 0 {
			t.Interval = interval
		}
		log.Printf("starting probe for %s", t.Name)
		go probe(t)
	}

	addr := conf.Addr
	if addr == "" {
		addr = defaultAddr
	}
	log.Printf("listening on %s", addr)
	err = http.ListenAndServe(addr, nil)
	fmt.Printf("exited: %v", err)
}
