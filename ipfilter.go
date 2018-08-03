package ipfilter

import (
	"log"
	"net"
	"net/http"
	"os"
	"sync"
)

//Options for IPFilter. Allowed takes precendence over Blocked.
//IPs can be IPv4 or IPv6 and can optionally contain subnet
//masks (/24). Note however, determining if a given IP is
//included in a subnet requires a linear scan so is less performant
//than looking up single IPs.
//
//This could be improved with some algorithmic magic.
type Options struct {
	//explicity allowed IPs
	AllowedIPs []string
	//explicity blocked IPs
	BlockedIPs []string
	//block by default (defaults to allow)
	BlockByDefault bool

	Logger interface {
		Printf(format string, v ...interface{})
	}
}

type IPFilter struct {
	opts Options
	//mut protects the below
	//rw since writes are rare
	mut            sync.RWMutex
	defaultAllowed bool
	ips            map[string]bool
	subnets        []*subnet
}

type subnet struct {
	str     string
	ipnet   *net.IPNet
	allowed bool
}

//who uses the new builtin anyway?
func new(opts Options) *IPFilter {
	if opts.Logger == nil {
		flags := log.LstdFlags
		opts.Logger = log.New(os.Stdout, "", flags)
	}
	f := &IPFilter{
		opts:           opts,
		ips:            map[string]bool{},
		defaultAllowed: !opts.BlockByDefault,
	}
	for _, ip := range opts.BlockedIPs {
		f.BlockIP(ip)
	}
	for _, ip := range opts.AllowedIPs {
		f.AllowIP(ip)
	}
	return f
}

//NewLazy performs database intilisation in a goroutine.
//will be skipped. Errors will be logged instead of returned.
func NewLazy(opts Options) *IPFilter {
	f := new(opts)
	return f
}

//New blocks during database intilisation and checks
//validity IP strings. returns an error on failure.
func New(opts Options) (*IPFilter, error) {
	f := new(opts)
	return f, nil
}

func (f *IPFilter) AllowIP(ip string) bool {
	return f.ToggleIP(ip, true)
}

func (f *IPFilter) BlockIP(ip string) bool {
	return f.ToggleIP(ip, false)
}

func (f *IPFilter) ToggleIP(str string, allowed bool) bool {
	//check if has subnet
	if ip, net, err := net.ParseCIDR(str); err == nil {
		// containing only one ip?
		if n, total := net.Mask.Size(); n == total {
			f.mut.Lock()
			f.ips[ip.String()] = allowed
			f.mut.Unlock()
			return true
		}
		//check for existing
		f.mut.Lock()
		found := false
		for _, subnet := range f.subnets {
			if subnet.str == str {
				found = true
				subnet.allowed = allowed
				break
			}
		}
		if !found {
			f.subnets = append(f.subnets, &subnet{
				str:     str,
				ipnet:   net,
				allowed: allowed,
			})
		}
		f.mut.Unlock()
		return true
	}
	//check if plain ip
	if ip := net.ParseIP(str); ip != nil {
		f.mut.Lock()
		f.ips[ip.String()] = allowed
		f.mut.Unlock()
		return true
	}
	return false
}

//ToggleDefault alters the default setting
func (f *IPFilter) ToggleDefault(allowed bool) {
	f.mut.Lock()
	f.defaultAllowed = allowed
	f.mut.Unlock()
}

//Allowed returns if a given IP can pass through the filter
func (f *IPFilter) Allowed(ipstr string) bool {
	return f.NetAllowed(net.ParseIP(ipstr))
}

//Allowed returns if a given net.IP can pass through the filter
func (f *IPFilter) NetAllowed(ip net.IP) bool {
	//invalid ip
	if ip == nil {
		return false
	}
	//read lock entire function
	//except for db access
	f.mut.RLock()
	defer f.mut.RUnlock()
	//check single ips
	allowed, ok := f.ips[ip.String()]
	if ok {
		return allowed
	}
	//scan subnets for any allow/block
	blocked := false
	for _, subnet := range f.subnets {
		if subnet.ipnet.Contains(ip) {
			if subnet.allowed {
				return true
			}
			blocked = true
		}
	}
	if blocked {
		return false
	}
	//use default setting
	return f.defaultAllowed
}

//Blocked returns if a given IP can NOT pass through the filter
func (f *IPFilter) Blocked(ip string) bool {
	return !f.Allowed(ip)
}

//Blocked returns if a given net.IP can NOT pass through the filter
func (f *IPFilter) NetBlocked(ip net.IP) bool {
	return !f.NetAllowed(ip)
}

//Wrap the provided handler with simple IP blocking middleware
//using this IP filter and its configuration
func (f *IPFilter) Wrap(next http.Handler) http.Handler {
	return &ipFilterMiddleware{IPFilter: f, next: next}
}

//Wrap is equivalent to NewLazy(opts) then Wrap(next)
func Wrap(next http.Handler, opts Options) http.Handler {
	return NewLazy(opts).Wrap(next)
}

type ipFilterMiddleware struct {
	*IPFilter
	next http.Handler
}

func (m *ipFilterMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//use remote addr as it cant be spoofed
	//TODO also check X-Fowarded-For and friends
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	//show simple forbidden text
	if !m.IPFilter.Allowed(ip) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	//success!
	m.next.ServeHTTP(w, r)
}
