// +build windows

package collector

import (
	"errors"
	"strconv"
	"strings"

	"github.com/StackExchange/wmi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"golang.org/x/sys/windows/registry"
)

func init() {
	Factories["cpu"] = NewCPUCollector
}

//A function to get windows version from registry

func getWindowsVersion() float64 {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		log.Warn("Couldn't open registry", err)
		return 0
	}
	defer func() {
		err = k.Close()
		if err != nil {
			log.Warnf("Failed to close registry key: %v", err)
		}
	}()

	currentv, _, err := k.GetStringValue("CurrentVersion")
	if err != nil {
		log.Warn("Couldn't open registry to determine current Windows version:", err)
		return 0
	}

	currentv_flt, err := strconv.ParseFloat(currentv, 64)

	log.Debugf("Detected Windows version %f\n", currentv_flt)

	return currentv_flt
}

// A CPUCollector is a Prometheus collector for WMI Win32_PerfRawData_PerfOS_Processor metrics
type CPUCollector struct {
	CStateSecondsTotal *prometheus.Desc
	TimeTotal          *prometheus.Desc
	InterruptsTotal    *prometheus.Desc
	DPCsTotal          *prometheus.Desc
	ProcessorFrequency *prometheus.Desc
	Cores              *prometheus.Desc
	ClockSpeed         *prometheus.Desc
	LogicalProcessors  *prometheus.Desc
}

// NewCPUCollector constructs a new CPUCollector
func NewCPUCollector() (Collector, error) {
	const subsystem = "cpu"
	return &CPUCollector{
		CStateSecondsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "cstate_seconds_total"),
			"Time spent in low-power idle state",
			[]string{"host", "core", "state"},
			nil,
		),
		TimeTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "time_total"),
			"Time that processor spent in different modes (idle, user, system, ...)",
			[]string{"host", "core", "mode"},
			nil,
		),

		InterruptsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "interrupts_total"),
			"Total number of received and serviced hardware interrupts",
			[]string{"host", "core"},
			nil,
		),
		DPCsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "dpcs_total"),
			"Total number of received and serviced deferred procedure calls (DPCs)",
			[]string{"host", "core"},
			nil,
		),
		Cores: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "cores"),
			"The physical CPU cores",
			[]string{"host"},
			nil,
		),
		ClockSpeed: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "clock_speed"),
			"The physical CPU clock speed",
			[]string{"host"},
			nil,
		),
		LogicalProcessors: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "logical_processors"),
			"ComputerSystem.NumberOfLogicalProcessors",
			[]string{"host"},
			nil,
		),
	}, nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *CPUCollector) Collect(ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ch); err != nil {
		log.Error("failed collecting cpu metrics:", desc, err)
		return err
	}
	return nil
}

// Win32_PerfRawData_PerfOS_Processor docs:
// - https://msdn.microsoft.com/en-us/library/aa394317(v=vs.90).aspx
type Win32_PerfRawData_PerfOS_Processor struct {
	Name                  string
	C1TransitionsPersec   uint64
	C2TransitionsPersec   uint64
	C3TransitionsPersec   uint64
	DPCRate               uint32
	DPCsQueuedPersec      uint32
	InterruptsPersec      uint32
	PercentC1Time         uint64
	PercentC2Time         uint64
	PercentC3Time         uint64
	PercentDPCTime        uint64
	PercentIdleTime       uint64
	PercentInterruptTime  uint64
	PercentPrivilegedTime uint64
	PercentProcessorTime  uint64
	PercentUserTime       uint64
}

type Win32_Processor struct {
	Name                      string
	NumberOfCores             uint32
	NumberOfLogicalProcessors uint32
	CurrentClockSpeed         uint32
	MaxClockSpeed             uint32
}

/*
type Win32_PerfRawData_Counters_ProcessorInformation struct {
	Name                        string
	AverageIdleTime             uint64
	C1TransitionsPersec         uint64
	C2TransitionsPersec         uint64
	C3TransitionsPersec         uint64
	ClockInterruptsPersec       uint64
	DPCRate                     uint64
	DPCsQueuedPersec            uint64
	IdleBreakEventsPersec       uint64
	InterruptsPersec            uint64
	ParkingStatus               uint64
	PercentC1Time               uint64
	PercentC2Time               uint64
	PercentC3Time               uint64
	PercentDPCTime              uint64
	PercentIdleTime             uint64
	PercentInterruptTime        uint64
	PercentofMaximumFrequency   uint64
	PercentPerformanceLimit     uint64
	PercentPriorityTime         uint64
	PercentPrivilegedTime       uint64
	PercentPrivilegedUtility    uint64
	PercentProcessorPerformance uint64
	PercentProcessorTime        uint64
	PercentProcessorUtility     uint64
	PercentUserTime             uint64
	PerformanceLimitFlags       uint64
	ProcessorFrequency          uint64
	ProcessorStateFlags         uint64
}*/

func (c *CPUCollector) collect(ch chan<- prometheus.Metric) (*prometheus.Desc, error) {
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

	var dst []Win32_PerfRawData_PerfOS_Processor
	q3 := queryAll(&dst)
	if err := wmi.Query(q3, &dst); err != nil {
		return nil, err
	}

	for _, data := range dst {
		if strings.Contains(data.Name, "_Total") {
			continue
		}

		core := data.Name

		// These are only available from Win32_PerfRawData_Counters_ProcessorInformation, which is only available from Win2008R2+
		/*ch <- prometheus.MustNewConstMetric(
			c.ProcessorFrequency,
			prometheus.GaugeValue,
			float64(data.ProcessorFrequency),
			socket, core,
		)
		ch <- prometheus.MustNewConstMetric(
			c.MaximumFrequency,
			prometheus.GaugeValue,
			float64(data.PercentofMaximumFrequency)/100*float64(data.ProcessorFrequency),
			socket, core,
		)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.CStateSecondsTotal,
				prometheus.GaugeValue,
				float64(data.PercentC1Time)*ticksToSecondsScaleFactor,
				hostName + " " + hostUUID, core, "c1",
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.CStateSecondsTotal,
				prometheus.GaugeValue,
				float64(data.PercentC2Time)*ticksToSecondsScaleFactor,
				hostName + " " + hostUUID, core, "c2",
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.CStateSecondsTotal,
				prometheus.GaugeValue,
				float64(data.PercentC3Time)*ticksToSecondsScaleFactor,
				hostName + " " + hostUUID, core, "c3",
			)*/

		ch <- prometheus.MustNewConstMetric(
			c.TimeTotal,
			prometheus.GaugeValue,
			float64(data.PercentIdleTime)*ticksToSecondsScaleFactor,
			hostName+" "+hostUUID, core, "idle",
		)
		ch <- prometheus.MustNewConstMetric(
			c.TimeTotal,
			prometheus.GaugeValue,
			float64(data.PercentInterruptTime)*ticksToSecondsScaleFactor,
			hostName+" "+hostUUID, core, "interrupt",
		)
		ch <- prometheus.MustNewConstMetric(
			c.TimeTotal,
			prometheus.GaugeValue,
			float64(data.PercentDPCTime)*ticksToSecondsScaleFactor,
			hostName+" "+hostUUID, core, "dpc",
		)
		ch <- prometheus.MustNewConstMetric(
			c.TimeTotal,
			prometheus.GaugeValue,
			float64(data.PercentPrivilegedTime)*ticksToSecondsScaleFactor,
			hostName+" "+hostUUID, core, "privileged",
		)
		ch <- prometheus.MustNewConstMetric(
			c.TimeTotal,
			prometheus.GaugeValue,
			float64(data.PercentUserTime)*ticksToSecondsScaleFactor,
			hostName+" "+hostUUID, core, "user",
		)

		/*		ch <- prometheus.MustNewConstMetric(
				c.InterruptsTotal,
				prometheus.CounterValue,
				float64(data.InterruptsPersec),
				hostName + " " + hostUUID, core,
			)*/
		/*		ch <- prometheus.MustNewConstMetric(
				c.DPCsTotal,
				prometheus.CounterValue,
				float64(data.DPCsQueuedPersec),
				hostName + " " + hostUUID, core,
			)*/
	}

	/*	var dst2 []Win32_Processor
		q4 := queryAll(&dst2)
		if err := wmi.Query(q4, &dst2); err != nil {
			return nil, err
		}

		if len(dst2) == 0 {
			return nil, errors.New("WMI query returned empty result set")
		}*/

	/*	ch <- prometheus.MustNewConstMetric(
		c.Cores,
		prometheus.GaugeValue,
		float64(dst2[0].NumberOfCores),
		hostName + " " + hostUUID,
	)*/

	/*	ch <- prometheus.MustNewConstMetric(
		c.ClockSpeed,
		prometheus.GaugeValue,
		float64(dst2[0].CurrentClockSpeed),
		hostName + " " + hostUUID,
	)*/

	/*	ch <- prometheus.MustNewConstMetric(
		c.LogicalProcessors,
		prometheus.GaugeValue,
		float64(dst2[0].NumberOfLogicalProcessors),
		hostName + " " + hostUUID,
	)*/

	return nil, nil
}
