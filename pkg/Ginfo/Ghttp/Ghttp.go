package Ghttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/4dogs-cn/TXPortMap/pkg/conversion"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// HTTP defines the plain http scheme
	HTTP = "http"
	// HTTPS defines the secure http scheme
	HTTPS = "https"
	// HTTPorHTTPS defines the both http and https scheme
	HTTPorHTTPS = "http|https"
)

type ScanOptions struct {
	Methods                []string
	StoreResponseDirectory string
	RequestURI             string
	RequestBody            string
	VHost                  bool
	OutputTitle            bool
	OutputStatusCode       bool
	OutputLocation         bool
	OutputContentLength    bool
	StoreResponse          bool
	OutputServerHeader     bool
	OutputWebSocket        bool
	OutputWithNoColor      bool
	OutputMethod           bool
	ResponseInStdout       bool
	TLSProbe               bool
	CSPProbe               bool
	OutputContentType      bool
	Unsafe                 bool
	Pipeline               bool
	HTTP2Probe             bool
	OutputIP               bool
	OutputCName            bool
	OutputCDN              bool
	OutputResponseTime     bool
	PreferHTTPS            bool
	NoFallback             bool
}

func Analyze(protocol, connectHost string, port int, method string, scanopts *ScanOptions, hostHeader string) Result {
	origProtocol := protocol
	if protocol == HTTP {
		protocol = HTTP
	} else if protocol == HTTPS {
		protocol = HTTPS
	} else {
		protocol = HTTPS
	}
	currentScheme := protocol
	retried := false

retry:
	if connectHost == "" && hostHeader == "" {
		return Result{err: errors.New("empty target host")}
	}

	dialHost := connectHost
	if dialHost == "" {
		dialHost = hostHeader
	}

	dialPort := port
	if dialPort <= 0 {
		dialPort = defaultPortForScheme(currentScheme)
	}
	effectivePort := port
	if effectivePort <= 0 {
		effectivePort = dialPort
	}

	dialAddr := net.JoinHostPort(dialHost, strconv.Itoa(dialPort))
	requestURL := buildURL(currentScheme, dialHost, effectivePort)
	displayHost := connectHost
	if hostHeader != "" {
		displayHost = hostHeader
	}
	displayURL := buildURL(currentScheme, displayHost, effectivePort)

	serverName := normalizeServerName(hostHeader, connectHost)

	dialer := &net.Dialer{Timeout: time.Second * 10}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddr)
		},
	}

	client := &http.Client{
		Timeout:   time.Second * 10,
		Transport: tr,
	}

	req, err := http.NewRequest(method, requestURL, nil)
	if err != nil {
		return Result{URL: displayURL, err: err}
	}
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36")
	if hostHeader != "" {
		req.Host = hostHeaderForRequest(hostHeader, currentScheme, effectivePort)
	}

	resp, err := client.Do(req)

	if err != nil {
		if !retried && origProtocol == HTTPorHTTPS {
			if currentScheme == HTTPS {
				currentScheme = HTTP
			} else {
				currentScheme = HTTPS
			}
			retried = true
			goto retry
		}
		return Result{URL: displayURL, err: err}
	}

	var fullURL string
	if resp.StatusCode >= 0 {
		fullURL = displayURL
	}

	builder := &strings.Builder{}
	builder.WriteString(fullURL)

	if scanopts.OutputStatusCode {
		builder.WriteString(" [")
		builder.WriteString(strconv.Itoa(resp.StatusCode))
		builder.WriteRune(']')
	}

	if scanopts.OutputContentLength {
		builder.WriteString(" [")
		builder.WriteString(strconv.FormatInt(resp.ContentLength, 10))
		builder.WriteRune(']')
	}

	if scanopts.OutputContentType {
		builder.WriteString(" [")
		builder.WriteString(resp.Header.Get("Content-Type"))
		builder.WriteRune(']')
	}

	defer resp.Body.Close()
	var titles []string
	body, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		title1 := ExtractTitle(string(body), resp)
		finger := ExtractFinger(string(body), resp)
		if title1 != "" {
			titles = append(titles, title1)
		}
		if finger != "" {
			titles = append(titles, finger)
		}
		if scanopts.OutputTitle {
			builder.WriteString(" [")
			builder.WriteString(strings.Join(titles, "|"))
			builder.WriteRune(']')
		}
	}
	title := strings.Join(titles, "|")

	serverHeader1 := resp.Header.Get("Server")
	serverHeader2 := resp.Header.Get("X-Powered-By")
	var serverHeaders []string
	if serverHeader1 != "" {
		serverHeaders = append(serverHeaders, serverHeader1)
	}
	if serverHeader2 != "" {
		serverHeaders = append(serverHeaders, serverHeader2)
	}
	serverHeader := strings.Join(serverHeaders, "|")

	if scanopts.OutputServerHeader {
		builder.WriteString(fmt.Sprintf(" [%s]", serverHeader))
	}

	// web socket
	isWebSocket := resp.StatusCode == 101
	if scanopts.OutputWebSocket && isWebSocket {
		builder.WriteString(" [websocket]")
	}

	return Result{
		URL:           fullURL,
		ContentLength: len(body),
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		Title:         title,
		WebServer:     serverHeader,
		str:           builder.String(),
	}
}

func defaultPortForScheme(scheme string) int {
	if scheme == HTTPS {
		return 443
	}
	return 80
}

func shouldIncludePort(scheme string, port int) bool {
	if port <= 0 {
		return false
	}
	return port != defaultPortForScheme(scheme)
}

func buildURL(scheme, host string, port int) string {
	if host == "" {
		return ""
	}
	if port > 0 {
		return fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func hostHeaderForRequest(host, scheme string, port int) string {
	if shouldIncludePort(scheme, port) {
		return fmt.Sprintf("%s:%d", host, port)
	}
	return host
}

func normalizeServerName(hostHeader, connectHost string) string {
	candidate := hostHeader
	if candidate == "" {
		candidate = connectHost
	}
	candidate = stripPort(candidate)
	if candidate == "" {
		return ""
	}
	if net.ParseIP(candidate) != nil {
		return ""
	}
	return candidate
}

func stripPort(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	if strings.HasPrefix(host, "[") {
		if idx := strings.LastIndex(host, "]"); idx != -1 {
			return host[1:idx]
		}
	}

	if strings.Count(host, ":") > 1 {
		return host
	}

	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}

	return host
}

// Result of a scan
type Result struct {
	URL           string `json:"url"`
	Title         string `json:"title"`
	WebServer     string `json:"webserver"`
	ContentType   string `json:"content-type,omitempty"`
	ContentLength int    `json:"content-length"`
	StatusCode    int    `json:"status-code"`
	err           error
	str           string
}

// JSON the result
func (r *Result) JSON() string {
	if js, err := json.Marshal(r); err == nil {
		return string(js)
	}

	return ""
}

func GetHttpTitle(target, hostOverride, proc string, port int) Result {
	var scanopts = new(ScanOptions)
	scanopts.OutputTitle = true
	scanopts.OutputServerHeader = true
	result := Analyze(proc, target, port, "GET", scanopts, hostOverride)
	return result
}

func (r *Result) ToString() string {

	builder := &bytes.Buffer{}
	if r.err == nil {
		builder.WriteString("[")
		builder.WriteString(conversion.ToString(r.StatusCode))
		builder.WriteString("] ")
		if r.WebServer != "" {
			builder.WriteString("[")
			builder.WriteString(r.WebServer)
			builder.WriteString("] ")
		}
		if r.Title != "" {
			builder.WriteString("[")
			builder.WriteString(r.Title)
			builder.WriteString("] ")
		}
	}

	return builder.String()
}

func hostsFrom(ss []string) []string {
	for i, s := range ss {
		u, _ := url.Parse(s)
		if host := u.Hostname(); host != "" {
			ss[i] = host
		}
	}
	return ss
}

type hostinfo struct {
	Host       string
	Port       int
	ServerName string
	Certs      []*x509.Certificate
}

func (h *hostinfo) getCerts(timeout time.Duration) error {
	//log.Printf("connecting to %s:%d", h.Host, h.Port)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		h.Host+":"+strconv.Itoa(h.Port),
		&tls.Config{
			InsecureSkipVerify: true,
			ServerName:         h.ServerName,
		})
	if err != nil {
		return err
	}

	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return err
	}

	pc := conn.ConnectionState().PeerCertificates
	h.Certs = make([]*x509.Certificate, 0, len(pc))
	for _, cert := range pc {
		if cert.IsCA {
			continue
		}
		h.Certs = append(h.Certs, cert)
	}

	return nil
}

func CertInfo(connectHost, serverName, port string, timeout time.Duration) (commonName string, dnsNames []string, err error) {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return commonName, dnsNames, err
	}
	info := hostinfo{Host: connectHost, Port: portInt, ServerName: serverName}
	err = info.getCerts(timeout)
	if err != nil {
		return commonName, dnsNames, err
	}
	for _, cert := range info.Certs {
		if cert != nil && cert.Subject.CommonName != "" {
			return cert.Subject.CommonName, cert.DNSNames, err
		}
	}
	return commonName, dnsNames, errors.New("not found")
}

func GetCert(connectHost, serverName string, port int) (string, error) {
	var CN string
	var DN []string
	var ret string
	var err error
	if port <= 0 {
		port = 443
	}
	normalized := normalizeServerName(serverName, connectHost)
	CN, DN, err = CertInfo(connectHost, normalized, strconv.Itoa(port), 5*time.Second)
	ret = "CommonName:" + CN + "; "
	if len(DN) > 0 {
		ret = ret + "DNSName:"
		ret = ret + DN[0]
	}
	return ret, err
}
