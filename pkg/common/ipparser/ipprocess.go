package ipparser

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

/**
  这个文件主要是包含一些对ip地址进行处理的函数和对域名进行解析相关的函数
*/

type domainCache struct {
	sync.RWMutex
	ipToHosts map[string][]string
}

var domainHostCache = &domainCache{
	ipToHosts: make(map[string][]string),
}

func (d *domainCache) add(host string, ips []string) {
	host = strings.TrimSpace(host)
	if host == "" || len(ips) == 0 {
		return
	}

	d.Lock()
	defer d.Unlock()

	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		exists := false
		for _, recorded := range d.ipToHosts[ip] {
			if strings.EqualFold(recorded, host) {
				exists = true
				break
			}
		}

		if !exists {
			d.ipToHosts[ip] = append(d.ipToHosts[ip], host)
		}
	}
}

func (d *domainCache) primary(ip string) (string, bool) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", false
	}

	d.RLock()
	defer d.RUnlock()

	hosts := d.ipToHosts[ip]
	if len(hosts) == 0 {
		return "", false
	}
	return hosts[0], true
}

func (d *domainCache) list(ip string) []string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}

	d.RLock()
	defer d.RUnlock()

	hosts := d.ipToHosts[ip]
	if len(hosts) == 0 {
		return nil
	}

	cp := make([]string, len(hosts))
	copy(cp, hosts)
	return cp
}

func rememberDomainHost(host string, ips []string) {
	domainHostCache.add(host, ips)
}

// PrimaryHost 返回解析记录中与IP绑定的第一个域名
func PrimaryHost(ip string) (string, bool) {
	return domainHostCache.primary(ip)
}

// AllHosts 返回与IP绑定的全部域名
func AllHosts(ip string) []string {
	return domainHostCache.list(ip)
}

// resetDomainHostCache 仅用于测试，清空域名缓存
func resetDomainHostCache() {
	domainHostCache.Lock()
	defer domainHostCache.Unlock()
	domainHostCache.ipToHosts = make(map[string][]string)
}

// ValidIpv4 判断Ip地址是否合法
func ValidIpv4(ip string) bool {
	if valid := net.ParseIP(ip); valid != nil {
		return true
	}

	return false
}

// 根据域名查找ip，一个域名可能对应多个ip
func DomainToIp(domain string) ([]string, string, error) {
	var fields []string
	var mask string
	var host = domain

	if strings.Contains(domain, "/") {
		fields = strings.Split(domain, "/")
		host = fields[0]
		mask = fields[1]
	}

	ips, err := ipFilter(host)

	if err != nil {
		// TODO:: 记录日志
		fmt.Println(err)
		return nil, "", err
	}

	rememberDomainHost(host, ips)

	return ips, mask, nil
}

// ParseIPv4 把ipv4地址解析为整数
func ParseIPv4(ipstr string) (uint64, error) {

	ip := big.NewInt(0)
	tmp := net.ParseIP(ipstr).To4()
	if tmp == nil {
		return 0, errors.New("Wrong ip addr")
	}
	ip.SetBytes(tmp)

	return ip.Uint64(), nil
}

// UnParseIPv4 把整数解析成ip地址
func UnParseIPv4(ip uint64) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func IsIP(ip string) (b bool) {
	if m, _ := regexp.MatchString("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/{0,1}[0-9]{0,2}$", ip); !m {
		return false
	}

	return true
}

func IsIPRange(ip string) bool {
	if m, _ := regexp.MatchString("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}-[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", ip); m {
		return true
	}

	parts := strings.Split(ip, "-")
	if len(parts) != 2 {
		return false
	}

	start := strings.TrimSpace(parts[0])
	end := strings.TrimSpace(parts[1])

	if !IsIP(start) {
		return false
	}

	if IsIP(end) {
		return true
	}

	if matched, _ := regexp.MatchString("^[0-9]{1,3}$", end); !matched {
		return false
	}

	segments := strings.Split(start, ".")
	if len(segments) != 4 {
		return false
	}

	lastOctet, err := strconv.Atoi(segments[3])
	if err != nil {
		return false
	}

	endOctet, err := strconv.Atoi(end)
	if err != nil {
		return false
	}

	if endOctet < 0 || endOctet > 255 {
		return false
	}

	return endOctet >= lastOctet
}

func CidrParse(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips = make([]string, 0, 100)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// exclude ipv6 addr
func ipFilter(host string) ([]string, error) {
	tmp := make([]string, 0, 50)

	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		if IsIP(ip) {
			tmp = append(tmp, ip)
		}
	}

	return tmp, nil
}
