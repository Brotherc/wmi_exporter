// +build windows

package collector

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/StackExchange/wmi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"gopkg.in/alecthomas/kingpin.v2"
)

func init() {
	Factories["net"] = NewNetworkCollector
}

var (
	nicWhitelist = kingpin.Flag(
		"collector.net.nic-whitelist",
		"Regexp of NIC:s to whitelist. NIC name must both match whitelist and not match blacklist to be included.",
	).Default(".+").String()
	nicBlacklist = kingpin.Flag(
		"collector.net.nic-blacklist",
		"Regexp of NIC:s to blacklist. NIC name must both match whitelist and not match blacklist to be included.",
	).Default("").String()
	nicNameToUnderscore = regexp.MustCompile("[^a-zA-Z0-9]")
)

// A NetworkCollector is a Prometheus collector for WMI Win32_PerfRawData_Tcpip_NetworkInterface metrics
type NetworkCollector struct {
	BytesReceivedTotal       *prometheus.Desc
	BytesSentTotal           *prometheus.Desc
	BytesTotal               *prometheus.Desc
	PacketsOutboundDiscarded *prometheus.Desc
	PacketsOutboundErrors    *prometheus.Desc
	PacketsTotal             *prometheus.Desc
	PacketsReceivedDiscarded *prometheus.Desc
	PacketsReceivedErrors    *prometheus.Desc
	PacketsReceivedTotal     *prometheus.Desc
	PacketsReceivedUnknown   *prometheus.Desc
	PacketsSentTotal         *prometheus.Desc
	CurrentBandwidth         *prometheus.Desc

	nicWhitelistPattern *regexp.Regexp
	nicBlacklistPattern *regexp.Regexp
}

// NewNetworkCollector ...
func NewNetworkCollector() (Collector, error) {
	const subsystem = "net"

	return &NetworkCollector{
		BytesReceivedTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "bytes_received_total"),
			"(Network.BytesReceivedPerSec)",
			[]string{"host", "nic"},
			nil,
		),
		BytesSentTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "bytes_sent_total"),
			"(Network.BytesSentPerSec)",
			[]string{"host", "nic"},
			nil,
		),
		BytesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "bytes_total"),
			"(Network.BytesTotalPerSec)",
			[]string{"host", "nic"},
			nil,
		),
		PacketsOutboundDiscarded: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_outbound_discarded"),
			"(Network.PacketsOutboundDiscarded)",
			[]string{"host", "nic"},
			nil,
		),
		PacketsOutboundErrors: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_outbound_errors"),
			"(Network.PacketsOutboundErrors)",
			[]string{"host", "nic"},
			nil,
		),
		PacketsReceivedDiscarded: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_received_discarded"),
			"(Network.PacketsReceivedDiscarded)",
			[]string{"host", "nic"},
			nil,
		),
		PacketsReceivedErrors: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_received_errors"),
			"(Network.PacketsReceivedErrors)",
			[]string{"host", "nic"},
			nil,
		),
		PacketsReceivedTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_received_total"),
			"(Network.PacketsReceivedPerSec)",
			[]string{"host", "nic"},
			nil,
		),
		PacketsReceivedUnknown: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_received_unknown"),
			"(Network.PacketsReceivedUnknown)",
			[]string{"host", "nic"},
			nil,
		),
		PacketsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_total"),
			"(Network.PacketsPerSec)",
			[]string{"host", "nic"},
			nil,
		),
		PacketsSentTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_sent_total"),
			"(Network.PacketsSentPerSec)",
			[]string{"host", "nic"},
			nil,
		),
		CurrentBandwidth: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "current_bandwidth"),
			"(Network.CurrentBandwidth)",
			[]string{"host", "nic"},
			nil,
		),

		nicWhitelistPattern: regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *nicWhitelist)),
		nicBlacklistPattern: regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *nicBlacklist)),
	}, nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *NetworkCollector) Collect(ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ch); err != nil {
		log.Error("failed collecting net metrics:", desc, err)
		return err
	}
	return nil
}

// mangleNetworkName mangles Network Adapter name (non-alphanumeric to _)
// that is used in Win32_PerfRawData_Tcpip_NetworkInterface.
func mangleNetworkName(name string) string {
	return nicNameToUnderscore.ReplaceAllString(name, "_")
}

// Win32_PerfRawData_Tcpip_NetworkInterface docs:
// - https://technet.microsoft.com/en-us/security/aa394340(v=vs.80)
type Win32_PerfRawData_Tcpip_NetworkInterface struct {
	BytesReceivedPerSec      uint64
	BytesSentPerSec          uint64
	BytesTotalPerSec         uint64
	Name                     string
	PacketsOutboundDiscarded uint64
	PacketsOutboundErrors    uint64
	PacketsPerSec            uint64
	PacketsReceivedDiscarded uint64
	PacketsReceivedErrors    uint64
	PacketsReceivedPerSec    uint64
	PacketsReceivedUnknown   uint64
	PacketsSentPerSec        uint64
	CurrentBandwidth         uint64
}

func (c *NetworkCollector) collect(ch chan<- prometheus.Metric) (*prometheus.Desc, error) {
	var dst_csproduct []Win32_ComputerSystemProduct
	q := queryAll(&dst_csproduct)
	if err := wmi.Query(q, &dst_csproduct); err != nil {
		return nil, err
	}

	if len(dst_csproduct) == 0 {
		return nil, errors.New("WMI query returned empty result set")
	}
	hostUUID := dst_csproduct[0].UUID

	var dst_os []Win32_OperatingSystem
	q2 := queryAll(&dst_os)
	if err := wmi.Query(q2, &dst_os); err != nil {
		return nil, err
	}

	if len(dst_os) == 0 {
		return nil, errors.New("WMI query returned empty result set")
	}
	hostName := dst_os[0].CSName

	var dst []Win32_PerfRawData_Tcpip_NetworkInterface

	q3 := queryAll(&dst)
	if err := wmi.Query(q3, &dst); err != nil {
		return nil, err
	}

	for _, nic := range dst {
		if c.nicBlacklistPattern.MatchString(nic.Name) ||
			!c.nicWhitelistPattern.MatchString(nic.Name) {
			continue
		}

		name := mangleNetworkName(nic.Name)
		if name == "" {
			continue
		}

		// Counters
		/*		ch <- prometheus.MustNewConstMetric(
				c.BytesReceivedTotal,
				prometheus.CounterValue,
				float64(nic.BytesReceivedPerSec),
				hostUUID, name,
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.BytesSentTotal,
				prometheus.CounterValue,
				float64(nic.BytesSentPerSec),
				hostUUID, name,
			)*/
		ch <- prometheus.MustNewConstMetric(
			c.BytesTotal,
			prometheus.CounterValue,
			float64(nic.BytesTotalPerSec),
			hostName+" "+hostUUID, name,
		)
		/*		ch <- prometheus.MustNewConstMetric(
				c.PacketsOutboundDiscarded,
				prometheus.CounterValue,
				float64(nic.PacketsOutboundDiscarded),
				hostUUID, name,
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.PacketsOutboundErrors,
				prometheus.CounterValue,
				float64(nic.PacketsOutboundErrors),
				hostUUID, name,
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.PacketsTotal,
				prometheus.CounterValue,
				float64(nic.PacketsPerSec),
				hostUUID, name,
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.PacketsReceivedDiscarded,
				prometheus.CounterValue,
				float64(nic.PacketsReceivedDiscarded),
				hostUUID, name,
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.PacketsReceivedErrors,
				prometheus.CounterValue,
				float64(nic.PacketsReceivedErrors),
				hostUUID, name,
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.PacketsReceivedTotal,
				prometheus.CounterValue,
				float64(nic.PacketsReceivedPerSec),
				hostUUID, name,
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.PacketsReceivedUnknown,
				prometheus.CounterValue,
				float64(nic.PacketsReceivedUnknown),
				hostUUID, name,
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.PacketsSentTotal,
				prometheus.CounterValue,
				float64(nic.PacketsSentPerSec),
				hostUUID, name,
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.CurrentBandwidth,
				prometheus.CounterValue,
				float64(nic.CurrentBandwidth),
				hostUUID, name,
			)*/
	}

	return nil, nil
}
