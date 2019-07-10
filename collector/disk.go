// +build windows

package collector

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/StackExchange/wmi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"gopkg.in/alecthomas/kingpin.v2"
)

func init() {
	Factories["disk_partition"] = NewLogicalDiskCollector
	Factories["disk"] = NewPhysicalDiskCollector
}

var (
	volumeWhitelist = kingpin.Flag(
		"collector.logical_disk.volume-whitelist",
		"Regexp of volumes to whitelist. Volume name must both match whitelist and not match blacklist to be included.",
	).Default(".+").String()
	volumeBlacklist = kingpin.Flag(
		"collector.logical_disk.volume-blacklist",
		"Regexp of volumes to blacklist. Volume name must both match whitelist and not match blacklist to be included.",
	).Default("").String()
)

// A LogicalDiskCollector is a Prometheus collector for WMI Win32_PerfRawData_PerfDisk_LogicalDisk metrics
type LogicalDiskCollector struct {
	RequestsQueued  *prometheus.Desc
	ReadBytesTotal  *prometheus.Desc
	ReadsTotal      *prometheus.Desc
	WriteBytesTotal *prometheus.Desc
	WritesTotal     *prometheus.Desc
	ReadTime        *prometheus.Desc
	WriteTime       *prometheus.Desc
	TotalSpace      *prometheus.Desc
	FreeSpace       *prometheus.Desc
	IdleTime        *prometheus.Desc
	SplitIOs        *prometheus.Desc

	volumeWhitelistPattern *regexp.Regexp
	volumeBlacklistPattern *regexp.Regexp
}

// A PhysicalDiskCollector is a Prometheus collector for WMI Win32_PerfRawData_PerfDisk_PhysicalDisk metrics
type PhysicalDiskCollector struct {
	ReadBytesTotal  *prometheus.Desc
	ReadsTotal      *prometheus.Desc
	WriteBytesTotal *prometheus.Desc
	WritesTotal     *prometheus.Desc
	ReadTime        *prometheus.Desc
	WriteTime       *prometheus.Desc
	TotalSpace      *prometheus.Desc
	FreeSpace       *prometheus.Desc
	SplitIOs        *prometheus.Desc
}

// NewLogicalDiskCollector ...
func NewLogicalDiskCollector() (Collector, error) {
	const subsystem = "disk_partition"

	return &LogicalDiskCollector{
		RequestsQueued: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "requests_queued"),
			"The number of requests queued to the disk (LogicalDisk.CurrentDiskQueueLength)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		ReadBytesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "read_bytes_total"),
			"The number of bytes transferred from the disk during read operations (LogicalDisk.DiskReadBytesPerSec)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		ReadsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "reads_total"),
			"The number of read operations on the disk (LogicalDisk.DiskReadsPerSec)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		WriteBytesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "write_bytes_total"),
			"The number of bytes transferred to the disk during write operations (LogicalDisk.DiskWriteBytesPerSec)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		WritesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "writes_total"),
			"The number of write operations on the disk (LogicalDisk.DiskWritesPerSec)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		ReadTime: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "read_seconds_total"),
			"Seconds that the disk was busy servicing read requests (LogicalDisk.PercentDiskReadTime)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		WriteTime: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "write_seconds_total"),
			"Seconds that the disk was busy servicing write requests (LogicalDisk.PercentDiskWriteTime)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		FreeSpace: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "free_bytes"),
			"Free space in bytes (LogicalDisk.PercentFreeSpace)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		TotalSpace: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "size_bytes"),
			"Total space in bytes (LogicalDisk.PercentFreeSpace_Base)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		IdleTime: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "idle_seconds_total"),
			"Seconds that the disk was idle (LogicalDisk.PercentIdleTime)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		SplitIOs: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "split_ios_total"),
			"The number of I/Os to the disk were split into multiple I/Os (LogicalDisk.SplitIOPerSec)",
			[]string{"disk", "volume", "partition"},
			nil,
		),

		volumeWhitelistPattern: regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *volumeWhitelist)),
		volumeBlacklistPattern: regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *volumeBlacklist)),
	}, nil
}

// NewPhysicalDiskCollector ...
func NewPhysicalDiskCollector() (Collector, error) {
	const subsystem = "disk"

	return &PhysicalDiskCollector{
		ReadBytesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "read_bytes_total"),
			"The number of bytes transferred from the disk during read operations (PhysicalDisk.DiskReadBytesPerSec)",
			[]string{"host", "disk"},
			nil,
		),

		ReadsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "reads_total"),
			"The number of read operations on the disk (PhysicalDisk.DiskReadsPerSec)",
			[]string{"host", "disk"},
			nil,
		),

		WriteBytesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "write_bytes_total"),
			"The number of bytes transferred to the disk during write operations (PhysicalDisk.DiskWriteBytesPerSec)",
			[]string{"host", "disk"},
			nil,
		),

		WritesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "writes_total"),
			"The number of write operations on the disk (PhysicalDisk.DiskWritesPerSec)",
			[]string{"host", "disk"},
			nil,
		),

		ReadTime: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "read_seconds_total"),
			"Seconds that the disk was busy servicing read requests (PhysicalDisk.PercentDiskReadTime)",
			[]string{"host", "disk"},
			nil,
		),

		WriteTime: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "write_seconds_total"),
			"Seconds that the disk was busy servicing write requests (PhysicalDisk.PercentDiskWriteTime)",
			[]string{"host", "disk"},
			nil,
		),

		FreeSpace: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "free_bytes"),
			"Free space in bytes (PhysicalDisk.PercentFreeSpace)",
			[]string{"host", "disk"},
			nil,
		),

		TotalSpace: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "size_bytes"),
			"The amount of storage space available (used and free) across all listed volumes or at the "+
				"specified mount point. On Linux, the space reserved for root is not counted in the available space.",
			[]string{"host", "disk"},
			nil,
		),

		SplitIOs: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "split_ios_total"),
			"The number of I/Os to the disk were split into multiple I/Os (LogicalDisk.SplitIOPerSec)",
			[]string{"host", "disk"},
			nil,
		),
	}, nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *LogicalDiskCollector) Collect(ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ch); err != nil {
		log.Error("failed collecting logical_disk metrics:", desc, err)
		return err
	}
	return nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *PhysicalDiskCollector) Collect(ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ch); err != nil {
		log.Error("failed collecting physical_disk metrics:", desc, err)
		return err
	}
	return nil
}

type Win32_PerfRawData_PerfDisk_LogicalDisk struct {
	Name                   string
	CurrentDiskQueueLength uint32
	DiskReadBytesPerSec    uint64
	DiskReadsPerSec        uint32
	DiskWriteBytesPerSec   uint64
	DiskWritesPerSec       uint32
	PercentDiskReadTime    uint64
	PercentDiskWriteTime   uint64
	PercentFreeSpace       uint32
	PercentFreeSpace_Base  uint32
	PercentIdleTime        uint64
	SplitIOPerSec          uint32
}

type Win32_PerfRawData_PerfDisk_PhysicalDisk struct {
	Name                 string
	DiskReadBytesPerSec  uint64
	DiskReadsPerSec      uint32
	DiskWriteBytesPerSec uint64
	DiskWritesPerSec     uint32
	PercentDiskReadTime  uint64
	PercentDiskWriteTime uint64
	SplitIOPerSec        uint32
}

type Win32_DiskPartition struct {
	DiskIndex uint32
	Size      uint64
	DeviceID  string
}

type Win32_LogicalDiskToPartition struct {
	Antecedent string
	Dependent  string
}

func (c *LogicalDiskCollector) collect(ch chan<- prometheus.Metric) (*prometheus.Desc, error) {
	var dst_diskToPartition []Win32_LogicalDiskToPartition
	q := queryAll(&dst_diskToPartition)
	if err := wmi.Query(q, &dst_diskToPartition); err != nil {
		return nil, err
	}

	logicalDiskToDisk := make(map[string]string)
	logicalDiskToPartition := make(map[string]string)

	for _, diskToPartition := range dst_diskToPartition {
		// \\LAPTOP-U9S8DGSA\root\cimv2:Win32_DiskPartition.DeviceID="Disk #1, Partition #1"
		antecedent := diskToPartition.Antecedent
		// \\LAPTOP-U9S8DGSA\root\cimv2:Win32_LogicalDisk.DeviceID="C:"
		dependent := diskToPartition.Dependent

		// "C:"
		str := strings.Split(dependent, "=")[1]
		// C:
		k := str[1 : len(str)-1]
		// "Disk #1, Partition #1"
		str2 := strings.Split(antecedent, "=")[1]
		// Disk #1
		disk := strings.Split(str2[1:len(str2)-1], ",")[0]
		// Partition #1
		partition := strings.Split(str2[1:len(str2)-1], ",")[1][1:]
		logicalDiskToDisk[k] = disk
		logicalDiskToPartition[k] = partition
	}

	var dst []Win32_PerfRawData_PerfDisk_LogicalDisk
	q2 := queryAll(&dst)
	if err := wmi.Query(q2, &dst); err != nil {
		return nil, err
	}

	for _, volume := range dst {
		if volume.Name == "_Total" ||
			c.volumeBlacklistPattern.MatchString(volume.Name) ||
			!c.volumeWhitelistPattern.MatchString(volume.Name) {
			continue
		}

		/*		ch <- prometheus.MustNewConstMetric(
				c.RequestsQueued,
				prometheus.GaugeValue,
				float64(volume.CurrentDiskQueueLength),
				logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.ReadBytesTotal,
				prometheus.CounterValue,
				float64(volume.DiskReadBytesPerSec),
				logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.ReadsTotal,
				prometheus.CounterValue,
				float64(volume.DiskReadsPerSec),
				logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.WriteBytesTotal,
				prometheus.CounterValue,
				float64(volume.DiskWriteBytesPerSec),
				logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.WritesTotal,
				prometheus.CounterValue,
				float64(volume.DiskWritesPerSec),
				logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.ReadTime,
				prometheus.CounterValue,
				float64(volume.PercentDiskReadTime)*ticksToSecondsScaleFactor,
				logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.WriteTime,
				prometheus.CounterValue,
				float64(volume.PercentDiskWriteTime)*ticksToSecondsScaleFactor,
				logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
			)*/

		ch <- prometheus.MustNewConstMetric(
			c.FreeSpace,
			prometheus.GaugeValue,
			float64(volume.PercentFreeSpace)*1024*1024,
			logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
		)

		/*		ch <- prometheus.MustNewConstMetric(
				c.TotalSpace,
				prometheus.GaugeValue,
				float64(volume.PercentFreeSpace_Base)*1024*1024,
				logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.IdleTime,
				prometheus.CounterValue,
				float64(volume.PercentIdleTime)*ticksToSecondsScaleFactor,
				logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.SplitIOs,
				prometheus.CounterValue,
				float64(volume.SplitIOPerSec),
				logicalDiskToDisk[volume.Name], volume.Name, logicalDiskToPartition[volume.Name],
			)*/
	}

	return nil, nil
}

func (c *PhysicalDiskCollector) collect(ch chan<- prometheus.Metric) (*prometheus.Desc, error) {
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

	var diskPartition []Win32_DiskPartition
	q3 := queryAll(&diskPartition)
	if err := wmi.Query(q3, &diskPartition); err != nil {
		return nil, err
	}

	diskSize := make(map[string]uint64)
	diskName := make(map[string]string)

	for _, partition := range diskPartition {

		if _, ok := diskName[fmt.Sprintf("%d", partition.DiskIndex)]; !ok {
			diskName[fmt.Sprintf("%d", partition.DiskIndex)] = strings.Split(partition.DeviceID, ",")[0]
		}

		if _, ok := diskSize[fmt.Sprintf("%d", partition.DiskIndex)]; ok {
			diskSize[fmt.Sprintf("%d", partition.DiskIndex)] += partition.Size
		} else {
			diskSize[fmt.Sprintf("%d", partition.DiskIndex)] = partition.Size
		}

	}

	var physicalDisk []Win32_PerfRawData_PerfDisk_PhysicalDisk
	q4 := queryAll(&physicalDisk)
	if err := wmi.Query(q4, &physicalDisk); err != nil {
		return nil, err
	}

	for _, disk := range physicalDisk {
		if disk.Name == "_Total" {
			continue
		}

		name := strings.Split(disk.Name, " ")[0]

		ch <- prometheus.MustNewConstMetric(
			c.ReadBytesTotal,
			prometheus.CounterValue,
			float64(disk.DiskReadBytesPerSec),
			hostUUID, diskName[name],
		)

		/*		ch <- prometheus.MustNewConstMetric(
				c.ReadsTotal,
				prometheus.CounterValue,
				float64(disk.DiskReadsPerSec),
				hostUUID, diskName[name],
			)*/

		ch <- prometheus.MustNewConstMetric(
			c.WriteBytesTotal,
			prometheus.CounterValue,
			float64(disk.DiskWriteBytesPerSec),
			hostName+" "+hostUUID, diskName[name],
		)

		/*		ch <- prometheus.MustNewConstMetric(
				c.WritesTotal,
				prometheus.CounterValue,
				float64(disk.DiskWritesPerSec),
				hostUUID, diskName[name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.ReadTime,
				prometheus.CounterValue,
				float64(disk.PercentDiskReadTime)*ticksToSecondsScaleFactor,
				hostUUID, diskName[name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.WriteTime,
				prometheus.CounterValue,
				float64(disk.PercentDiskWriteTime)*ticksToSecondsScaleFactor,
				hostUUID, diskName[name],
			)*/

		/*		ch <- prometheus.MustNewConstMetric(
				c.SplitIOs,
				prometheus.CounterValue,
				float64(disk.SplitIOPerSec),
				hostUUID, diskName[name],
			)*/

		/*		fmt.Println("AvgDiskBytesPerRead")
				fmt.Println(disk.AvgDiskBytesPerRead)
				fmt.Println("AvgDiskBytesPerWrite")
				fmt.Println(disk.AvgDiskBytesPerWrite)*/
		/*		fmt.Println("AvgDiskSecPerRead")
				fmt.Println(float64(disk.AvgDiskBytesPerRead)/(float64(disk.AvgDiskSecPerRead)*ticksToSecondsScaleFactor))
				fmt.Println("AvgDiskSecPerWrite")
				fmt.Println(float64(disk.AvgDiskBytesPerWrite)/(float64(disk.AvgDiskSecPerWrite)*ticksToSecondsScaleFactor))*/
	}

	for k, v := range diskSize {
		ch <- prometheus.MustNewConstMetric(
			c.TotalSpace,
			prometheus.GaugeValue,
			float64(v),
			hostName+" "+hostUUID, diskName[k],
		)
	}

	return nil, nil
}
