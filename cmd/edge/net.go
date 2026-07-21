package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func (e *edge) netInfo() ([]string, []string, bool) {
	if len(e.publicIPs) > 0 {
		return e.publicIPs, e.localIPs, e.isPrivate
	}
	return discoverNetworkInfo()
}

func createIPClient(networkType string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				return dialer.DialContext(ctx, networkType, addr)
			},
		},
	}
}

func isAccessibleIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}

	if ipv4[0] == 10 ||
		(ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31) ||
		(ipv4[0] == 192 && ipv4[1] == 168) {
		return false
	}

	if ipv4[0] == 100 && (ipv4[1] >= 64 && ipv4[1] <= 127) {
		return false
	}

	if ipv4[0] == 127 {
		return false
	}

	if ipv4[0] == 169 && ipv4[1] == 254 {
		return false
	}

	return true
}

func discoverIPs() (ipv4 string, ipv6 string, isIPv4Accessible bool) {
	clientV4 := createIPClient("tcp4")
	resp, err := clientV4.Get("https://ipify.org")
	if err == nil && resp.StatusCode == http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ipv4 = strings.TrimSpace(string(b))
	}

	clientV6 := createIPClient("tcp6")
	resp, err = clientV6.Get("https://ipinfo.io")
	if err == nil && resp.StatusCode == http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ipv6 = strings.TrimSpace(string(b))
	}

	isIPv4Accessible = isAccessibleIPv4(ipv4)

	return ipv4, ipv6, isIPv4Accessible
}

func discoverNetworkInfo() (publicIPs, localIPs []string, isPrivate bool) {
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				localIPs = append(localIPs, ipnet.IP.String())
			}
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err == nil && resp.StatusCode == 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		v4 := strings.TrimSpace(string(b))
		if v4 != "" {
			publicIPs = append(publicIPs, v4)
		}
	} else {
		resp, err = client.Get("https://ifconfig.me/ip")
		if err == nil && resp.StatusCode == 200 {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			ip := strings.TrimSpace(string(b))
			if ip != "" && len(publicIPs) == 0 {
				publicIPs = append(publicIPs, ip)
			}
		}
	}

	resp, err = client.Get("https://api6.ipify.org")
	if err == nil && resp.StatusCode == 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		v6 := strings.TrimSpace(string(b))
		if v6 != "" {
			publicIPs = append(publicIPs, v6)
		}
	}

	for _, ip := range publicIPs {
		if isPrivateIP(ip) {
			isPrivate = true
		}
	}
	for _, ip := range localIPs {
		if isPrivateIP(ip) {
			isPrivate = true
		}
	}

	return
}

func isPrivateIP(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
			return true
		case ip.IsLinkLocalUnicast():
			return true
		}
	}
	return false
}

func remoteAddrIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	default:
		return addr.String()
	}
}

func deviceID() string {
	h := sha256.New()
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		h.Write(b)
	}
	if b, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		h.Write(b)
	}
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		h.Write(b)
	}
	if host, err := os.Hostname(); err == nil {
		h.Write([]byte(host))
	}
	if addrs, err := net.Interfaces(); err == nil {
		for _, a := range addrs {
			if len(a.HardwareAddr) > 0 {
				h.Write(a.HardwareAddr)
			}
		}
	}
	if b := readPlatformUUID(); len(b) > 0 {
		h.Write(b)
	}
	id := fmt.Sprintf("%x", h.Sum(nil)[:16])
	os.WriteFile(edgeIDFile(), []byte(id), 0644)
	return id
}

func readPlatformUUID() []byte {
	if b, err := os.ReadFile("C:\\Windows\\System32\\license.rtf"); err == nil && len(b) > 0 {
		h := sha256.Sum256(b)
		return h[:]
	}
	if b, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					uuid := strings.TrimSpace(parts[1])
					uuid = strings.Trim(uuid, "\"")
					return []byte(uuid)
				}
			}
		}
	}
	return nil
}

func edgeIDFile() string {
	cache, _ := os.UserCacheDir()
	if cache == "" {
		cache = "/tmp"
	}
	return cache + "/mscope-edge-id"
}
