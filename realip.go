package realip

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

var privateCidrs []*net.IPNet
var cloudFlareCidrs []*net.IPNet

func init() {
	maxCidrBlocks := []string{
		"127.0.0.1/8",    // localhost
		"10.0.0.0/8",     // 24-bit block
		"172.16.0.0/12",  // 20-bit block
		"192.168.0.0/16", // 16-bit block
		"169.254.0.0/16", // link local address
		"::1/128",        // localhost IPv6
		"fc00::/7",       // unique local address IPv6
		"fe80::/10",      // link local address IPv6
	}

	cloudFlareCidrBlocks := []string{
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"104.16.0.0/12",
		"108.162.192.0/18",
		"131.0.72.0/22",
		"141.101.64.0/18",
		"162.158.0.0/15",
		"172.64.0.0/13",
		"173.245.48.0/20",
		"188.114.96.0/20",
		"190.93.240.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
	}

	privateCidrs = parseCidrs(maxCidrBlocks)
	cloudFlareCidrs = parseCidrs(cloudFlareCidrBlocks)
}

func parseCidrs(raw []string) (cidrs []*net.IPNet) {
	cidrs = make([]*net.IPNet, len(raw))
	for i, block := range raw {
		_, cidr, _ := net.ParseCIDR(block)
		cidrs[i] = cidr
	}
	return
}

// isLocalAddress works by checking if the address is under private CIDR blocks.
// List of private CIDR blocks can be seen on :
//
// https://en.wikipedia.org/wiki/Private_network
//
// https://en.wikipedia.org/wiki/Link-local_address
func isPrivateAddress(address string) (bool, error) {
	return isUnderCIDRBlocks(address, privateCidrs)
}

// isCloudFlareAddress checks if the IP address is under CIDR blocks provided by CloudFlare.
// List of CloudFlare's CIDR blocks can be seen on:
// https://www.cloudflare.com/ips-v4
func isCloudFlareAddress(address string) (bool, error) {
	return isUnderCIDRBlocks(address, cloudFlareCidrs)
}

func isUnderCIDRBlocks(address string, blocks []*net.IPNet) (bool, error) {
	ipAddress := net.ParseIP(address)
	if ipAddress == nil {
		return false, errors.New("address is not valid")
	}

	for i := range blocks {
		if blocks[i].Contains(ipAddress) {
			return true, nil
		}
	}

	return false, nil
}

// FromRequest return client's real public IP address from http request
func FromRequest(r *http.Request, trustedProxies... *net.IPNet) string {
	// Fetch header value
	xRealIP := r.Header.Get("X-Real-Ip")
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	remoteAddr := r.RemoteAddr
	return FromHeaders(xRealIP, xForwardedFor, remoteAddr, trustedProxies...)
}

// FromHeaders return client's real public IP Address from http request headers.
func FromHeaders(xRealIP string, xForwardedFor string, remoteAddr string, trustedProxies... *net.IPNet) string {
	// If there are colon in remote address, remove the port number
	// otherwise, return remote address as is
	var remoteIP string
	if strings.ContainsRune(remoteAddr, ':') {
		remoteIP, _, _ = net.SplitHostPort(remoteAddr)
	} else {
		remoteIP = remoteAddr
	}
	isPrivate, err := isPrivateAddress(remoteIP)
	isCloudFlare, err := isCloudFlareAddress(remoteIP)
	isProxy, err := isUnderCIDRBlocks(remoteIP, trustedProxies)
	if !isPrivate && !isCloudFlare && !isProxy && err == nil {
		return remoteIP
	}

	// Try to get IP address from X-Forwarded-For header
	if xForwardedFor != "" {
		forwardedForIps := strings.Split(xForwardedFor, ",")

		// Check a inverted list of IP adresses in X-Forwarded-For and return the first global address which is not an IP adress of one of trusted proxy
		// By iterating a inverted list prevent IP spoofing
		for i := len(forwardedForIps) - 1; i >= 0; i-- {
			address := strings.TrimSpace(forwardedForIps[i])
			isPrivate, err := isPrivateAddress(address)
			isCloudFlare, err := isCloudFlareAddress(address)
			isProxy, err := isUnderCIDRBlocks(address, trustedProxies)
			if !isPrivate && !isCloudFlare && !isProxy && err == nil {
				return address
			}
		}
	}

	// Try to get IP address from X-Real-IP header
	xRealIP = strings.TrimSpace(xRealIP)
	if xRealIP != "" {
		isPrivate, err := isPrivateAddress(xRealIP)
		isCloudFlare, err := isCloudFlareAddress(xRealIP)
		isProxy, err := isUnderCIDRBlocks(xRealIP, trustedProxies)
		if !isPrivate && !isCloudFlare && !isProxy && err == nil {
			return xRealIP
		}
	}

	// If nothing succeed, just return remote address
	return remoteIP
}

// RealIP is depreciated, use FromRequest instead
func RealIP(r *http.Request) string {
	return FromRequest(r)
}
