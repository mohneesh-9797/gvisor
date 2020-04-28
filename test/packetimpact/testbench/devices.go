// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testbench

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

type deviceInfo struct {
	mac      net.HardwareAddr
	ipv4Addr net.IP
	ipv4Net  *net.IPNet
	ipv6Addr net.IP
	ipv6Net  *net.IPNet
}

var deviceLine = regexp.MustCompile(`^\s*\d+: (\w+)`)
var linkLine = regexp.MustCompile(`^\s*link/\w+ ([0-9a-fA-F:]+)`)
var inetLine = regexp.MustCompile(`^\s*inet ([0-9./]+)`)
var inet6Line = regexp.MustCompile(`^\s*inet6 ([0-9a-fA-Z:/]+)`)

// listDevices returns a map from device name to information about the device.
func listDevices() (map[string]deviceInfo, error) {
	out, err := exec.Command("ip", "addr", "show").Output()
	if err != nil {
		return nil, err
	}
	fmt.Println(string(out))
	var currentDevice string
	var currentInfo deviceInfo
	deviceInfos := make(map[string]deviceInfo)
	for _, line := range strings.Split(string(out), "\n") {
		if m := deviceLine.FindStringSubmatch(line); m != nil {
			if currentDevice != "" {
				deviceInfos[currentDevice] = currentInfo
			}
			currentInfo = deviceInfo{}
			currentDevice = m[1]
		} else if m := linkLine.FindStringSubmatch(line); m != nil {
			mac, err := net.ParseMAC(m[1])
			if err != nil {
				return nil, err
			}
			currentInfo.mac = mac
		} else if m := inetLine.FindStringSubmatch(line); m != nil {
			ipv4Addr, ipv4Net, err := net.ParseCIDR(m[1])
			if err != nil {
				return nil, err
			}
			currentInfo.ipv4Addr = ipv4Addr
			currentInfo.ipv4Net = ipv4Net
		} else if m := inet6Line.FindStringSubmatch(line); m != nil {
			ipv6Addr, ipv6Net, err := net.ParseCIDR(m[1])
			if err != nil {
				return nil, err
			}
			currentInfo.ipv6Addr = ipv6Addr
			currentInfo.ipv6Net = ipv6Net
		}
	}
	if currentDevice != "" {
		deviceInfos[currentDevice] = currentInfo
	}
	return deviceInfos, nil
}

// Convert the MAC address to an IPv6 link local address as described in RFC
// 4291 page 20: https://tools.ietf.org/html/rfc4291#page-20
func macToIP(mac net.HardwareAddr) net.IP {
	// Split the octets of the MAC into an array of strings.
	return net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, mac[0], mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
}

// deviceByIP finds a deviceInfo and device name from an IP address.
func deviceByIP(ip net.IP) (string, deviceInfo, error) {
	devices, err := listDevices()
	if err != nil {
		return "", deviceInfo{}, fmt.Errorf("unable to listDevices: %w", err)
	}
	for dev, info := range devices {
		if info.ipv4Addr.Equal(ip) {
			return dev, info, nil
		}
	}
	return "", deviceInfo{}, fmt.Errorf("can't find %v on any interface", ip)
}
