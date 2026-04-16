/*
Example of how to extend github.com/ldkingvivi/cidranger

# This adds ASN as a string field, along with methods to get the ASN and the CIDR as strings

Thank you to yl2chen for his assistance and work on this library.
*/
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/ldkingvivi/cidranger"
)

// customRangerEntry represents an entry with an associated IP network and autonomous system number (ASN).
type customRangerEntry struct {
	ipNet net.IPNet
	asn   string
}

// Network returns the IP network associated with the customRangerEntry instance.
func (b *customRangerEntry) Network() net.IPNet {
	return b.ipNet
}

// NetworkStr returns the string representation of the associated IP network.
func (b *customRangerEntry) NetworkStr() string {
	return b.ipNet.String()
}

// Asn returns the autonomous system number (ASN) associated with the customRangerEntry instance.
func (b *customRangerEntry) Asn() string {
	return b.asn
}

// newCustomRangerEntry creates and returns a new RangerEntry with the specified IP network and autonomous system
// number (ASN).
func newCustomRangerEntry(ipNet net.IPNet, asn string) cidranger.RangerEntry {
	return &customRangerEntry{
		ipNet: ipNet,
		asn:   asn,
	}
}

func main() {
	// Instantiate NewPCTrieRanger.
	ranger := cidranger.NewPCTrieRanger()

	// Load sample data using our custom function.
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	ranger.Insert(newCustomRangerEntry(*network, "0001"))

	_, network, _ = net.ParseCIDR("128.168.1.0/24")
	ranger.Insert(newCustomRangerEntry(*network, "0002"))

	// Check if IP is contained within ranger.
	contains, err := ranger.Contains(net.ParseIP("128.168.1.7"))
	if err != nil {
		fmt.Println("ranger.Contains()", err.Error())
		os.Exit(1)
	}
	fmt.Println("Contains:", contains)

	// Request networks containing this IP.
	ip := "192.168.1.42"
	entries, err := ranger.ContainingNetworks(net.ParseIP(ip))
	if err != nil {
		fmt.Println("ranger.ContainingNetworks()", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Entries for %s:\n", ip)
	for _, e := range entries {
		// Cast e (cidranger.RangerEntry to struct customRangerEntry.
		entry, ok := e.(*customRangerEntry)
		if !ok {
			continue
		}

		// Get network (converted to string by function).
		n := entry.NetworkStr()

		// Get ASN.
		a := entry.Asn()

		// Display.
		fmt.Println("\t", n, a)
	}
}
