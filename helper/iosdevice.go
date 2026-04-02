package helper

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const defaultCmdTimeout = 10 * time.Second

// DeviceInfo holds parsed iOS device metadata.
type DeviceInfo struct {
	Platform     string  `json:"platform"`
	Name         *string `json:"name"`
	Model        *string `json:"model"`
	OSVersion    *string `json:"osVersion"`
	SerialNumber *string `json:"serialNumber"`
	UDID         *string `json:"udid"`
	ModelNumber  *string `json:"modelNumber"`
	CPUArch      *string `json:"cpuArch"`
	Colour       *string `json:"colour"`
	IMEI         *string `json:"imei"`
	IMEI2        *string `json:"imei2"`
	MACAddress   *string `json:"macAddress"`
	SIMNumber    *string `json:"simNumber"`
	ROM          *string `json:"rom"`
}

// InstalledApp represents a single installed application.
type InstalledApp struct {
	BundleID string `json:"bundleId"`
	Version  string `json:"version"`
	Name     string `json:"name"`
}

var deviceIDRegex = regexp.MustCompile(`^[A-Za-z0-9\-]+$`)
var bundleIDRegex = regexp.MustCompile(`^[A-Za-z0-9.\-]+$`)

func validateDeviceID(id string) bool {
	return id != "" && len(id) <= 64 && deviceIDRegex.MatchString(id)
}

func validateBundleID(id string) bool {
	return id != "" && len(id) <= 256 && bundleIDRegex.MatchString(id)
}

func validateIPAPath(path string) error {
	cleaned := filepath.Clean(path)
	if !strings.HasSuffix(strings.ToLower(cleaned), ".ipa") {
		return fmt.Errorf("not an .ipa file")
	}
	info, err := os.Lstat(cleaned)
	if err != nil {
		return fmt.Errorf("file not found: %s", cleaned)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", cleaned)
	}
	return nil
}

func strPtr(s string) *string {
	return &s
}

func parseDeviceList(output string) []string {
	var ids []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && validateDeviceID(trimmed) {
			ids = append(ids, trimmed)
		}
	}
	return ids
}

func parseIdeviceInfo(output string) DeviceInfo {
	info := DeviceInfo{Platform: "iOS"}
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		switch key {
		case "DeviceName":
			info.Name = strPtr(value)
		case "ProductType":
			info.Model = strPtr(value)
		case "ProductVersion":
			info.OSVersion = strPtr(value)
		case "SerialNumber":
			info.SerialNumber = strPtr(value)
		case "UniqueDeviceID":
			info.UDID = strPtr(value)
		case "ModelNumber":
			cleaned := strings.Split(value, "/")[0]
			cleaned = strings.Split(cleaned, "\\")[0]
			info.ModelNumber = strPtr(strings.TrimSpace(cleaned))
		case "CPUArchitecture":
			arch := strings.ToLower(value)
			switch {
			case strings.Contains(arch, "arm64") || strings.Contains(arch, "aarch64"):
				info.CPUArch = strPtr("ARM64")
			case strings.Contains(arch, "x86_64"):
				info.CPUArch = strPtr("x86_64")
			case strings.Contains(arch, "arm"):
				info.CPUArch = strPtr("ARM")
			default:
				info.CPUArch = strPtr(value)
			}
		case "InternationalMobileEquipmentIdentity":
			info.IMEI = strPtr(value)
		case "IntegratedCircuitCardIdentity":
			info.SIMNumber = strPtr(value)
		case "WiFiAddress":
			info.MACAddress = strPtr(value)
		case "BuildVersion":
			info.ROM = strPtr(value)
		}
	}
	return info
}

func parseInstalledApps(output string) []InstalledApp {
	var apps []InstalledApp
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // skip header
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		parts := strings.SplitN(trimmed, ",", 3)
		if len(parts) != 3 {
			continue
		}
		apps = append(apps, InstalledApp{
			BundleID: strings.TrimSpace(parts[0]),
			Version:  strings.Trim(strings.TrimSpace(parts[1]), `"`),
			Name:     strings.Trim(strings.TrimSpace(parts[2]), `"`),
		})
	}
	return apps
}

// runCmd executes a command with a timeout and returns stdout.
func runCmd(cmdName string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, cmdName, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// DetectDevice lists connected iOS devices using idevice_id.
func DetectDevice() ([]string, error) {
	output, err := runCmd("idevice_id", "-l")
	if err != nil {
		return nil, fmt.Errorf("idevice_id: %w", err)
	}
	return parseDeviceList(output), nil
}

// PairDevice pairs/trusts a connected iOS device.
func PairDevice(deviceID string) error {
	output, err := runCmd("idevicepair", "-u", deviceID, "pair")
	if err != nil {
		return fmt.Errorf("idevicepair: %w", err)
	}
	if !strings.Contains(output, "SUCCESS") {
		return fmt.Errorf("trust not completed — tap \"Trust\" on your iPhone and try again")
	}
	return nil
}

// FetchDeviceInfo retrieves device metadata using ideviceinfo.
func FetchDeviceInfo(deviceID string) (DeviceInfo, error) {
	output, err := runCmd("ideviceinfo", "-u", deviceID)
	if err != nil {
		return DeviceInfo{Platform: "iOS"}, fmt.Errorf("ideviceinfo: %w", err)
	}
	return parseIdeviceInfo(output), nil
}

// InstallApp installs an IPA on a device using ideviceinstaller.
func InstallApp(deviceID, ipaPath string) error {
	_, err := runCmd("ideviceinstaller", "-u", deviceID, "-i", ipaPath)
	if err != nil {
		return fmt.Errorf("ideviceinstaller install: %w", err)
	}
	return nil
}

// UninstallApp removes an app by bundle ID using ideviceinstaller.
func UninstallApp(deviceID, bundleID string) error {
	_, err := runCmd("ideviceinstaller", "-u", deviceID, "-U", bundleID)
	if err != nil {
		return fmt.Errorf("ideviceinstaller uninstall: %w", err)
	}
	return nil
}

// ListApps lists installed apps on a device using ideviceinstaller.
func ListApps(deviceID string) ([]InstalledApp, error) {
	output, err := runCmd("ideviceinstaller", "-u", deviceID, "-l")
	if err != nil {
		return nil, fmt.Errorf("ideviceinstaller list: %w", err)
	}
	return parseInstalledApps(output), nil
}
