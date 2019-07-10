// +build windows

package collector

import (
	"errors"
	"fmt"
	"github.com/StackExchange/wmi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

func init() {
	Factories["system"] = NewSystemCollector
}

// A SystemCollector is a Prometheus collector for WMI metrics
type SystemCollector struct {
	ContextSwitchesTotal     *prometheus.Desc
	ExceptionDispatchesTotal *prometheus.Desc
	ProcessorQueueLength     *prometheus.Desc
	SystemCallsTotal         *prometheus.Desc
	SystemUpTime             *prometheus.Desc
	NumOfThreads             *prometheus.Desc
}

// NewSystemCollector ...
func NewSystemCollector() (Collector, error) {
	const subsystem = "system"
	const subsystem_host = "host"

	return &SystemCollector{
		ContextSwitchesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "context_switches_total"),
			"Total number of context switches (WMI source: PerfOS_System.ContextSwitchesPersec)",
			nil,
			nil,
		),
		ExceptionDispatchesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "exception_dispatches_total"),
			"Total number of exceptions dispatched (WMI source: PerfOS_System.ExceptionDispatchesPersec)",
			nil,
			nil,
		),
		ProcessorQueueLength: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "processor_queue_length"),
			"Length of processor queue (WMI source: PerfOS_System.ProcessorQueueLength)",
			nil,
			nil,
		),
		SystemCallsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "system_calls_total"),
			"Total number of system calls (WMI source: PerfOS_System.SystemCallsPersec)",
			nil,
			nil,
		),
		SystemUpTime: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem_host, "up_time"),
			"The host uptime since last start up (WMI source: PerfOS_System.SystemUpTime)",
			[]string{"host"},
			nil,
		),
		NumOfThreads: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem_host, "num_of_threads"),
			"Total threads count (WMI source: PerfOS_System.Threads)",
			[]string{"host"},
			nil,
		),
	}, nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *SystemCollector) Collect(ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ch); err != nil {
		log.Error("failed collecting system metrics:", desc, err)
		return err
	}
	return nil
}

// Win32_PerfRawData_PerfOS_System docs:
// - https://web.archive.org/web/20050830140516/http://msdn.microsoft.com/library/en-us/wmisdk/wmi/win32_perfrawdata_perfos_system.asp
type Win32_PerfRawData_PerfOS_System struct {
	ContextSwitchesPersec     uint32
	ExceptionDispatchesPersec uint32
	Frequency_Object          uint64
	ProcessorQueueLength      uint32
	SystemCallsPersec         uint32
	SystemUpTime              uint64
	Threads                   uint32
	Timestamp_Object          uint64
}

type Win32_NetworkAdapterConfiguration struct {
	IPAddress []string
}

type Win32_ComputerSystemProduct struct {
	UUID string
}

func (c *SystemCollector) collect(ch chan<- prometheus.Metric) (*prometheus.Desc, error) {
	var dst_csproduct []Win32_ComputerSystemProduct
	q := queryAll(&dst_csproduct)
	if err := wmi.Query(q, &dst_csproduct); err != nil {
		return nil, err
	}

	if len(dst_csproduct) == 0 {
		return nil, errors.New("WMI query returned empty result set")
	}
	hostUUID := dst_csproduct[0].UUID

	var dst []Win32_PerfRawData_PerfOS_System
	q2 := queryAll(&dst)
	if err := wmi.Query(q2, &dst); err != nil {
		return nil, err
	}
	if len(dst) == 0 {
		return nil, errors.New("WMI query returned empty result set")
	}

	/*	ch <- prometheus.MustNewConstMetric(
		c.ContextSwitchesTotal,
		prometheus.CounterValue,
		float64(dst[0].ContextSwitchesPersec),
	)*/
	/*	ch <- prometheus.MustNewConstMetric(
		c.ExceptionDispatchesTotal,
		prometheus.CounterValue,
		float64(dst[0].ExceptionDispatchesPersec),
	)*/
	/*	ch <- prometheus.MustNewConstMetric(
		c.ProcessorQueueLength,
		prometheus.GaugeValue,
		float64(dst[0].ProcessorQueueLength),
	)*/
	/*	ch <- prometheus.MustNewConstMetric(
		c.SystemCallsTotal,
		prometheus.CounterValue,
		float64(dst[0].SystemCallsPersec),
	)*/
	ch <- prometheus.MustNewConstMetric(
		c.SystemUpTime,
		prometheus.GaugeValue,
		// convert from Windows timestamp (1 jan 1601) to unix timestamp (1 jan 1970)
		float64(dst[0].SystemUpTime-116444736000000000)/float64(dst[0].Frequency_Object),
		hostUUID,
	)
	/*	ch <- prometheus.MustNewConstMetric(
		c.NumOfThreads,
		prometheus.GaugeValue,
		float64(dst[0].Threads),
		hostUUID,
	)*/

	/*	fmt.Println("====host====" + "hostId(The calculated identifier of the pyhsical Host):" + hostUUID)*/

	var dst_netAdapterCfg []Win32_NetworkAdapterConfiguration
	q3 := queryAll(&dst_netAdapterCfg)
	if err := wmi.Query(q3, &dst_netAdapterCfg); err != nil {
		return nil, err
	}

	if len(dst_netAdapterCfg) == 0 {
		return nil, errors.New("WMI query returned empty result set")
	}

	fmt.Println("====host====" + "ipAddresses(List of IP addresses):")
	for _, data := range dst_netAdapterCfg {
		if len(data.IPAddress) != 0 {
			fmt.Println(data.IPAddress)
		}
	}

	var dst_cs []Win32_ComputerSystem
	q4 := queryAll(&dst_cs)
	if err := wmi.Query(q4, &dst_cs); err != nil {
		return nil, err
	}

	if len(dst_cs) == 0 {
		return nil, errors.New("WMI query returned empty result set")
	}

	if dst_cs[0].Model == "VirtualBox" || dst_cs[0].Model == "Virtual Machine" || dst_cs[0].Model == "VMware Virtual Platform" {
		fmt.Println("====host====" + "该主机为虚拟机")
	}

	return nil, nil
}
