package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

type certFilePathList []string

func (i *certFilePathList) String() string {
	return "target certificate file path"
}

const (
	namespace = "apns"
)

var (
	listenAddress  = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(":9542").String()
	connectSuccess = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "connect_success"),
		"If the connection to pushgateway was a success",
		nil, nil,
	)

	notAfter = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cert_not_after"),
		"NotAfter expressed as a Unix Epoch Time",
		nil, nil,
	)
)

type Collector struct {
	target string
	logger log.Logger
}

type CertResult struct {
	notAfter       time.Time
	connectSuccess bool
}

func collectCertMetrics(certPath string, logger log.Logger) (*CertResult, error) {

	certFile, err := os.Open(certPath)
	if err != nil {
		return nil, err
	}

	defer certFile.Close()

	certFileInfo, _ := certFile.Stat()
	var size = certFileInfo.Size()
	certBytes := make([]byte, size)
	buf := bufio.NewReader(certFile)
	_, err = buf.Read(certBytes)

	block, _ := pem.Decode([]byte(certBytes))
	cert, err := x509.ParseCertificate(block.Bytes)

	level.Info(logger).Log("msg", "Certificate Info", "NotAfter", cert.NotAfter)

	c, err := tls.LoadX509KeyPair(certPath, certPath)
	if err != nil {
		level.Info(logger).Log("msg", "failed key pair load", "tls.LoadX509KeyPair", err)
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{c},
	}
	host := "gateway.sandbox.push.apple.com:2195"
	conn, err := tls.Dial("tcp", host, tlsConfig)

	if err != nil {
		level.Error(logger).Log("msg", "failed verification", "verify", err)
		return nil, err
	}
	defer conn.Close()

	return &CertResult{
		notAfter:       cert.NotAfter,
		connectSuccess: true,
	}, nil
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- connectSuccess
	ch <- notAfter
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	certPath := c.target
	result, err := collectCertMetrics(certPath, c.logger)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(
			connectSuccess, prometheus.GaugeValue, 0,
		)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		connectSuccess, prometheus.GaugeValue, 1,
	)

	if !result.notAfter.IsZero() {
		ch <- prometheus.MustNewConstMetric(
			notAfter, prometheus.GaugeValue, float64(result.notAfter.Unix()),
		)
	}
}

func handler(w http.ResponseWriter, r *http.Request, logger log.Logger) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "Target parameter is missing", 400)
		return
	}
	registry := prometheus.NewRegistry()
	collector := &Collector{target, logger}
	registry.MustRegister(collector)
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func main() {
	logConfig := promlog.Config{
		Level:  &promlog.AllowedLevel{},
		Format: &promlog.AllowedFormat{},
	}
	flag.AddFlags(kingpin.CommandLine, &logConfig)
	kingpin.Version(version.Print("cert_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(&logConfig)

	http.HandleFunc("/export", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, logger)
	})
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server")
		os.Exit(1)
	}

}
