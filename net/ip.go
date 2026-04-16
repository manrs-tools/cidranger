/*
Package net provides utility functions for working with IPs (net.IP).
*/
package net

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
)

// IPVersion is the version of IP address.
type IPVersion string

// Helper constants.
const (
	IPv4Uint32Count = 1
	IPv6Uint32Count = 4

	BitsPerUint32 = 32
	BytePerUint32 = 4

	IPv4 IPVersion = "IPv4"
	IPv6 IPVersion = "IPv6"
)

// ErrInvalidBitPosition is returned when bits requested is not valid.
var ErrInvalidBitPosition = fmt.Errorf("bit position not valid")

// ErrVersionMismatch is returned upon mismatch in network input versions.
var ErrVersionMismatch = fmt.Errorf("network input version mismatch")

// ErrNoGreatestCommonBit is an error returned when no greatest common bit
// exists for the cidr ranges.
var ErrNoGreatestCommonBit = fmt.Errorf("no greatest common bit")

// NetworkNumber represents an IP address using uint32 as internal storage.
// IPv4 usings 1 uint32, while IPv6 uses 4 uint32.
type NetworkNumber []uint32

// NewNetworkNumber returns an equivalent NetworkNumber to the given IP address,
// Returns nil if ip is neither IPv4 nor IPv6.
func NewNetworkNumber(ip net.IP) NetworkNumber {
	if ip == nil {
		return nil
	}
	coercedIP := ip.To4()
	parts := 1
	if coercedIP == nil {
		coercedIP = ip.To16()
		parts = 4
	}
	if coercedIP == nil {
		return nil
	}
	nn := make(NetworkNumber, parts)
	for i := 0; i < parts; i++ {
		idx := i * net.IPv4len
		nn[i] = binary.BigEndian.Uint32(coercedIP[idx : idx+net.IPv4len])
	}
	return nn
}

// ToV4 returns ip address if ip is IPv4, returns nil otherwise.
func (n NetworkNumber) ToV4() NetworkNumber {
	if len(n) != IPv4Uint32Count {
		return nil
	}
	return n
}

// ToV6 returns ip address if ip is IPv6, returns nil otherwise.
func (n NetworkNumber) ToV6() NetworkNumber {
	if len(n) != IPv6Uint32Count {
		return nil
	}
	return n
}

// ToIP returns equivalent net.IP.
func (n NetworkNumber) ToIP() net.IP {
	ip := make(net.IP, len(n)*BytePerUint32)
	for i := range n {
		idx := i * net.IPv4len
		binary.BigEndian.PutUint32(ip[idx:idx+net.IPv4len], n[i])
	}
	if len(ip) == net.IPv4len {
		ip = net.IPv4(ip[0], ip[1], ip[2], ip[3])
	}
	return ip
}

// Equal is the equality test for 2 network numbers.
func (n NetworkNumber) Equal(n1 NetworkNumber) bool {
	if len(n) != len(n1) {
		return false
	}
	if n[0] != n1[0] {
		return false
	}
	if len(n) == IPv6Uint32Count {
		return n[1] == n1[1] && n[2] == n1[2] && n[3] == n1[3]
	}
	return true
}

// Next returns the next logical network number.
func (n NetworkNumber) Next() NetworkNumber {
	newIP := make(NetworkNumber, len(n))
	copy(newIP, n)
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] > 0 {
			break
		}
	}
	return newIP
}

// Previous returns the previous logical network number.
func (n NetworkNumber) Previous() NetworkNumber {
	newIP := make(NetworkNumber, len(n))
	copy(newIP, n)
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]--
		if newIP[i] < math.MaxUint32 {
			break
		}
	}
	return newIP
}

// Bit returns a uint32 representing the bit value at a given position, e.g.,
// "128.0.0.0" has a bit value of 1 at position 31, and 0 for positions 30 to 0.
func (n NetworkNumber) Bit(position uint) (uint32, error) {
	if int(position) > len(n)*BitsPerUint32-1 {
		return 0, ErrInvalidBitPosition
	}
	idx := len(n) - 1 - int(position/BitsPerUint32)
	// Mod 31 to get array index.
	rShift := position & (BitsPerUint32 - 1)
	return (n[idx] >> rShift) & 1, nil
}

// LeastCommonBitPosition returns the smallest differing bit position between two NetworkNumbers or an error if invalid.
func (n NetworkNumber) LeastCommonBitPosition(n1 NetworkNumber) (uint, error) {
	if len(n) != len(n1) {
		return 0, ErrVersionMismatch
	}
	for i := range n {
		mask := uint32(1) << 31
		pos := uint(31)
		for ; mask > 0; mask >>= 1 {
			if n[i]&mask != n1[i]&mask {
				if i == 0 && pos == 31 {
					return 0, ErrNoGreatestCommonBit
				}
				return (pos + 1) + uint(BitsPerUint32)*uint(len(n)-i-1), nil
			}
			pos--
		}
	}
	return 0, nil
}

// Network represents a block of network numbers, also known as CIDR.
type Network struct {
	net.IPNet
	Number NetworkNumber
	Mask   NetworkNumberMask
}

// isZeros checks if all bytes in the given net.IP are zero and returns true if they are, false otherwise.
func isZeros(p net.IP) bool {
	for i := range p {
		if p[i] != 0 {
			return false
		}
	}
	return true
}

// NewNetwork creates a new Network instance from the provided net.IPNet, adjusting the mask for IPv4-mapped addresses.
func NewNetwork(ipNet net.IPNet) Network {
	if len(ipNet.IP) == net.IPv6len && isZeros(ipNet.IP[0:10]) && ipNet.IP[10] == 0xff && ipNet.IP[11] == 0xff {
		ipNet.Mask = ipNet.Mask[12:]
	}

	return Network{
		IPNet:  ipNet,
		Number: NewNetworkNumber(ipNet.IP),
		Mask:   NetworkNumberMask(NewNetworkNumber(net.IP(ipNet.Mask))),
	}
}

// Masked applies a CIDR mask with the specified number of leading ones to the Network and returns the resulting
// Network.
func (n Network) Masked(ones int) Network {
	mask := net.CIDRMask(ones, len(n.Number)*BitsPerUint32)
	return NewNetwork(net.IPNet{
		IP:   n.IP.Mask(mask),
		Mask: mask,
	})
}

// Contains checks whether the given NetworkNumber lies within the range defined by the Network.
func (n Network) Contains(nn NetworkNumber) bool {
	if len(n.Mask) != len(nn) {
		return false
	}
	if nn[0]&n.Mask[0] != n.Number[0] {
		return false
	}
	if len(nn) == IPv6Uint32Count {
		return nn[1]&n.Mask[1] == n.Number[1] && nn[2]&n.Mask[2] == n.Number[2] && nn[3]&n.Mask[3] == n.Number[3]
	}
	return true
}

// Covers checks whether the current network fully encompasses the given network, validating both range and mask size.
func (n Network) Covers(o Network) bool {
	if len(n.Number) != len(o.Number) {
		return false
	}
	nMaskSize, _ := n.IPNet.Mask.Size()
	oMaskSize, _ := o.IPNet.Mask.Size()
	return n.Contains(o.Number) && nMaskSize <= oMaskSize
}

// LeastCommonBitPosition calculates the least common differing bit position between two Networks considering their
// masks.
func (n Network) LeastCommonBitPosition(n1 Network) (uint, error) {
	maskSize, _ := n.IPNet.Mask.Size()
	if maskSize1, _ := n1.IPNet.Mask.Size(); maskSize1 < maskSize {
		maskSize = maskSize1
	}
	maskPosition := len(n1.Number)*BitsPerUint32 - maskSize
	lcb, err := n.Number.LeastCommonBitPosition(n1.Number)
	if err != nil {
		return 0, err
	}
	return uint(math.Max(float64(maskPosition), float64(lcb))), nil
}

// Equal is the equality test for 2 networks.
func (n Network) Equal(n1 Network) bool {
	return bytes.Equal(n.IPNet.IP, n1.IPNet.IP) && bytes.Equal(n.IPNet.Mask, n1.IPNet.Mask)
}

func (n Network) String() string {
	return n.IPNet.String()
}

// NetworkNumberMask is an IP address.
type NetworkNumberMask NetworkNumber

// Mask returns a new masked NetworkNumber from a given NetworkNumber.
func (m NetworkNumberMask) Mask(n NetworkNumber) (NetworkNumber, error) {
	if len(m) != len(n) {
		return nil, ErrVersionMismatch
	}
	result := make(NetworkNumber, len(m))
	result[0] = m[0] & n[0]
	if len(m) == IPv6Uint32Count {
		result[1] = m[1] & n[1]
		result[2] = m[2] & n[2]
		result[3] = m[3] & n[3]
	}
	return result, nil
}

// NextIP returns the next sequential ip.
func NextIP(ip net.IP) net.IP {
	return NewNetworkNumber(ip).Next().ToIP()
}

// PreviousIP returns the previous sequential ip.
func PreviousIP(ip net.IP) net.IP {
	return NewNetworkNumber(ip).Previous().ToIP()
}
