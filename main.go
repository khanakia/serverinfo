package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
)

type IPInfo struct {
	IP     string `json:"ip"`
	CIDR   string `json:"cidr"`
	Family string `json:"family"` // "ipv4" or "ipv6"
	Scope  string `json:"scope"`  // "loopback", "link-local", "global", etc.
}

type InterfaceInfo struct {
	Name         string   `json:"name"`
	Index        int      `json:"index"`
	MTU          int      `json:"mtu"`
	HardwareAddr string   `json:"hardware_addr"`
	Flags        []string `json:"flags"`
	IPs          []IPInfo `json:"ips"`
}

func flagsToStrings(flags net.Flags) []string {
	var out []string
	if flags&net.FlagUp != 0 {
		out = append(out, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		out = append(out, "broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		out = append(out, "loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		out = append(out, "point-to-point")
	}
	if flags&net.FlagMulticast != 0 {
		out = append(out, "multicast")
	}
	return out
}

func scopeForIP(ip net.IP) string {
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link-local"
	}
	return "global"
}

// getAllInterfaces collects all network interfaces and their addresses.
func getAllInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []InterfaceInfo

	for _, iface := range ifaces {
		ii := InterfaceInfo{
			Name:         iface.Name,
			Index:        iface.Index,
			MTU:          iface.MTU,
			HardwareAddr: iface.HardwareAddr.String(),
			Flags:        flagsToStrings(iface.Flags),
		}

		addrs, err := iface.Addrs()
		if err != nil {
			// skip address errors for a specific interface
			continue
		}

		for _, addr := range addrs {
			var (
				ip   net.IP
				cidr string
			)

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				cidr = v.String()
			case *net.IPAddr:
				ip = v.IP
				cidr = v.String()
			}

			if ip == nil {
				continue
			}

			family := "unknown"
			if ip.To4() != nil {
				family = "ipv4"
			} else if ip.To16() != nil {
				family = "ipv6"
			}

			ii.IPs = append(ii.IPs, IPInfo{
				IP:     ip.String(),
				CIDR:   cidr,
				Family: family,
				Scope:  scopeForIP(ip),
			})
		}

		result = append(result, ii)
	}

	return result, nil
}

func ipHandler(w http.ResponseWriter, r *http.Request) {
	interfaces, err := getAllInterfaces()
	if err != nil {
		http.Error(w, "could not list interfaces: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(interfaces); err != nil {
		http.Error(w, "failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {
	http.HandleFunc("/ip", ipHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := ":" + port
	log.Printf("Server listening on %s (GET /ip)\n", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
