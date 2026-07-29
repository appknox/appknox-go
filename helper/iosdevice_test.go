package helper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseIdeviceInfo(t *testing.T) {
	output := `ActivationState: Activated
BuildVersion: 21F90
CPUArchitecture: arm64e
DeviceName: My iPhone
InternationalMobileEquipmentIdentity: 351234567890123
IntegratedCircuitCardIdentity: 8901234567890123456
ModelNumber: MQ6M3
ProductType: iPhone15,2
ProductVersion: 17.5.1
SerialNumber: ABCDE12345
UniqueDeviceID: 00001111-000A1234B567890C
WiFiAddress: a1:b2:c3:d4:e5:f6`

	info := parseIdeviceInfo(output)

	assert.Equal(t, "iOS", info.Platform)
	assert.Equal(t, "My iPhone", *info.Name)
	assert.Equal(t, "iPhone15,2", *info.Model)
	assert.Equal(t, "17.5.1", *info.OSVersion)
	assert.Equal(t, "ABCDE12345", *info.SerialNumber)
	assert.Equal(t, "00001111-000A1234B567890C", *info.UDID)
	assert.Equal(t, "MQ6M3", *info.ModelNumber)
	assert.Equal(t, "ARM64", *info.CPUArch)
	assert.Equal(t, "351234567890123", *info.IMEI)
	assert.Equal(t, "8901234567890123456", *info.SIMNumber)
	assert.Equal(t, "a1:b2:c3:d4:e5:f6", *info.MACAddress)
	assert.Equal(t, "21F90", *info.ROM)
}

func TestParseIdeviceInfoEmpty(t *testing.T) {
	info := parseIdeviceInfo("")
	assert.Equal(t, "iOS", info.Platform)
	assert.Nil(t, info.Name)
}

func TestValidateDeviceID(t *testing.T) {
	assert.True(t, validateDeviceID("00001111-000A1234B567890C"))
	assert.True(t, validateDeviceID("abcdef1234567890"))
	assert.False(t, validateDeviceID(""))
	assert.False(t, validateDeviceID("id;rm -rf /"))
	assert.False(t, validateDeviceID("id with spaces"))
}

func TestParseDeviceList(t *testing.T) {
	output := "00001111-000A1234B567890C\nabcdef1234567890\n"
	ids := parseDeviceList(output)
	assert.Equal(t, []string{"00001111-000A1234B567890C", "abcdef1234567890"}, ids)
}

func TestParseDeviceListEmpty(t *testing.T) {
	ids := parseDeviceList("")
	assert.Empty(t, ids)
}

func TestParseDeviceListFiltersInvalid(t *testing.T) {
	output := "valid-id-123\n;bad;id;\nok456\n"
	ids := parseDeviceList(output)
	assert.Equal(t, []string{"valid-id-123", "ok456"}, ids)
}

func TestValidateBundleID(t *testing.T) {
	assert.True(t, validateBundleID("com.example.app"))
	assert.True(t, validateBundleID("com.another-app.test"))
	assert.False(t, validateBundleID(""))
	assert.False(t, validateBundleID("com.bad;app"))
	assert.False(t, validateBundleID("com.bad app"))
}

func TestValidateIPAPath(t *testing.T) {
	assert.Error(t, validateIPAPath(""))
	assert.Error(t, validateIPAPath("/tmp/app.apk"))
	assert.Error(t, validateIPAPath("/nonexistent/path/app.ipa"))
}

func TestParseInstalledApps(t *testing.T) {
	output := `CFBundleIdentifier, CFBundleVersion, CFBundleDisplayName
com.example.app, "1.0", "Example App"
com.another.app, "2.3.1", "Another App"`

	apps := parseInstalledApps(output)
	assert.Len(t, apps, 2)
	assert.Equal(t, "com.example.app", apps[0].BundleID)
	assert.Equal(t, "1.0", apps[0].Version)
	assert.Equal(t, "Example App", apps[0].Name)
	assert.Equal(t, "com.another.app", apps[1].BundleID)
}
