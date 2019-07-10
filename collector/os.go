// +build windows

package collector

import (
	"errors"
	"fmt"
	"time"

	"github.com/StackExchange/wmi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

func init() {
	Factories["os"] = NewOSCollector
}

// A OSCollector is a Prometheus collector for WMI metrics
type OSCollector struct {
	PhysicalMemoryFreeBytes *prometheus.Desc
	PagingFreeBytes         *prometheus.Desc
	VirtualMemoryFreeBytes  *prometheus.Desc
	ProcessesLimit          *prometheus.Desc
	ProcessMemoryLimitBytes *prometheus.Desc
	NumOfProcesses          *prometheus.Desc
	Users                   *prometheus.Desc
	PagingTotalBytes        *prometheus.Desc
	VirtualMemoryBytes      *prometheus.Desc
	VisibleMemoryBytes      *prometheus.Desc
	Time                    *prometheus.Desc
	Timezone                *prometheus.Desc
	OSType                  *prometheus.Desc
	Name                    *prometheus.Desc
	OSArchitecture          *prometheus.Desc
}

// NewOSCollector ...
func NewOSCollector() (Collector, error) {
	const subsystem = "os"
	const subsystem_host = "host"
	const subsystem_memory = "memory"

	return &OSCollector{
		PagingTotalBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem_memory, "paging_total_bytes"),
			"The total amount of allocated page file.",
			[]string{"host"},
			nil,
		),
		PagingFreeBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem_memory, "paging_free_bytes"),
			"OperatingSystem.FreeSpaceInPagingFiles",
			[]string{"host"},
			nil,
		),
		PhysicalMemoryFreeBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem_memory, "physical_memory_free_bytes"),
			"OperatingSystem.FreePhysicalMemory",
			[]string{"host"},
			nil,
		),
		Time: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "time"),
			"OperatingSystem.LocalDateTime",
			nil,
			nil,
		),
		Timezone: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "timezone"),
			"OperatingSystem.LocalDateTime",
			[]string{"timezone"},
			nil,
		),
		NumOfProcesses: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem_host, "num_of_processes"),
			"Total processes count(OperatingSystem.NumberOfProcesses)",
			[]string{"host"},
			nil,
		),
		ProcessesLimit: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "processes_limit"),
			"OperatingSystem.MaxNumberOfProcesses",
			nil,
			nil,
		),
		ProcessMemoryLimitBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "process_memory_limix_bytes"),
			"OperatingSystem.MaxProcessMemorySize",
			nil,
			nil,
		),
		Users: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "users"),
			"OperatingSystem.NumberOfUsers",
			nil,
			nil,
		),
		VirtualMemoryBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem_memory, "virtual_memory_bytes"),
			"OperatingSystem.TotalVirtualMemorySize",
			[]string{"host"},
			nil,
		),
		VisibleMemoryBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem_memory, "visible_memory_bytes"),
			"The total amount of memory.",
			[]string{"host"},
			nil,
		),
		VirtualMemoryFreeBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem_memory, "virtual_memory_free_bytes"),
			"OperatingSystem.FreeVirtualMemory",
			[]string{"host"},
			nil,
		),
		OSType: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem_host, "os_type"),
			"It could be \"Windows\",\"Linux\", \"Mac\"",
			[]string{"host"},
			nil,
		),
	}, nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *OSCollector) Collect(ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ch); err != nil {
		log.Error("failed collecting os metrics:", desc, err)
		return err
	}
	return nil
}

type Win32_OperatingSystem struct {
	FreePhysicalMemory      uint64
	FreeSpaceInPagingFiles  uint64
	FreeVirtualMemory       uint64
	MaxNumberOfProcesses    uint32
	MaxProcessMemorySize    uint64
	NumberOfProcesses       uint32
	NumberOfUsers           uint32
	SizeStoredInPagingFiles uint64
	TotalVirtualMemorySize  uint64
	TotalVisibleMemorySize  uint64
	LocalDateTime           time.Time
	CSName                  string
	OSType                  uint16
	Name                    string
	OSArchitecture          string
}

var osType = map[uint16]string{
	58:    "Win2000",
	101:   "XP",
	102:   "Win2003",
	18:    "Windows NT",
	8:     "HPUX",
	29:    "Solaris",
	9:     "AIX",
	36:    "LINUX",
	6:     "Tru64",
	7:     "OpenVMS",
	107:   "OpenVMS (Itanium)",
	65535: "SNMP",
	0:     "Unknown",
}

func (c *OSCollector) collect(ch chan<- prometheus.Metric) (*prometheus.Desc, error) {
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

	var dst []Win32_OperatingSystem
	q3 := queryAll(&dst)
	if err := wmi.Query(q3, &dst); err != nil {
		return nil, err
	}

	if len(dst) == 0 {
		return nil, errors.New("WMI query returned empty result set")
	}

	ch <- prometheus.MustNewConstMetric(
		c.PhysicalMemoryFreeBytes,
		prometheus.GaugeValue,
		float64(dst[0].FreePhysicalMemory*1024), // KiB -> bytes
		hostName+" "+hostUUID,
	)

	/*	localDateTime := dst[0].LocalDateTime

		ch <- prometheus.MustNewConstMetric(
			c.Time,
			prometheus.GaugeValue,
			float64(localDateTime.Unix()),
		)

		timezoneName, _ := localDateTime.Zone()

		ch <- prometheus.MustNewConstMetric(
			c.Timezone,
			prometheus.GaugeValue,
			1.0,
			timezoneName,
		)*/

	/*	ch <- prometheus.MustNewConstMetric(
		c.PagingFreeBytes,
		prometheus.GaugeValue,
		float64(dst[0].FreeSpaceInPagingFiles*1024), // KiB -> bytes
		hostName + " " + hostUUID,
	)*/

	/*	ch <- prometheus.MustNewConstMetric(
		c.VirtualMemoryFreeBytes,
		prometheus.GaugeValue,
		float64(dst[0].FreeVirtualMemory*1024), // KiB -> bytes
		hostName + " " + hostUUID,
	)*/

	/*	ch <- prometheus.MustNewConstMetric(
		c.ProcessesLimit,
		prometheus.GaugeValue,
		float64(dst[0].MaxNumberOfProcesses),
	)*/

	/*	ch <- prometheus.MustNewConstMetric(
		c.ProcessMemoryLimitBytes,
		prometheus.GaugeValue,
		float64(dst[0].MaxProcessMemorySize*1024), // KiB -> bytes
	)*/

	ch <- prometheus.MustNewConstMetric(
		c.NumOfProcesses,
		prometheus.GaugeValue,
		float64(dst[0].NumberOfProcesses),
		hostName+" "+hostUUID,
	)

	/*	ch <- prometheus.MustNewConstMetric(
		c.Users,
		prometheus.GaugeValue,
		float64(dst[0].NumberOfUsers),
	)*/

	/*	ch <- prometheus.MustNewConstMetric(
		c.PagingTotalBytes,
		prometheus.GaugeValue,
		float64(dst[0].SizeStoredInPagingFiles*1024), // KiB -> bytes
		hostName + " " + hostUUID,
	)*/

	/*	ch <- prometheus.MustNewConstMetric(
		c.VirtualMemoryBytes,
		prometheus.GaugeValue,
		float64(dst[0].TotalVirtualMemorySize*1024), // KiB -> bytes
		hostName + " " + hostUUID,
	)*/

	ch <- prometheus.MustNewConstMetric(
		c.VisibleMemoryBytes,
		prometheus.GaugeValue,
		float64(dst[0].TotalVisibleMemorySize*1024), // KiB -> bytes
		hostName+" "+hostUUID,
	)

	/*	ch <- prometheus.MustNewConstMetric(
		c.OSType,
		prometheus.GaugeValue,
		float64(dst[0].OSType),
		hostName + " " + hostUUID,
	)*/

	fmt.Println("====host====" + "osType(It could be \"Windows\",\"Linux\", \"Mac\"):" + osType[dst[0].OSType])
	fmt.Println("====host====" + "osName(The os name, version and architecture, sample: \"Windows 10 x64\"):" +
		dst[0].Name + " " + dst[0].OSArchitecture)

	return nil, nil
}
