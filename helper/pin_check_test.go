package helper

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const nscBase = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">example.com</domain>
    </domain-config>
</network-security-config>
`

func withPin(digest string) string {
	return strings.Replace(nscBase, "</domain>\n", "</domain>\n        <pin-set>\n            <pin digest=\"SHA-256\">"+
		digest+"</pin>\n        </pin-set>\n", 1)
}

// eShop 83, 2026-10-02: the fixer added <pin digest="SHA-256">AAAA...=</pin>.
// The scanner is satisfied; the shipped app refuses every TLS connection to
// the domain. A pin is the server's real key digest or no pin at all.
func TestCheckAddedPins(t *testing.T) {
	path := "app/src/main/res/xml/network_security_config.xml"
	real := "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="
	require.Nil(t, checkAddedPins(path, nscBase, withPin(real)))
	require.Nil(t, checkAddedPins(path, withPin(real), withPin(real)), "an existing pin is not this patch's")
	for _, bad := range []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		"YOUR_PIN_HERE",
		"base64==",
		"SPKI_SHA256_BASE64",
	} {
		v := checkAddedPins(path, nscBase, withPin(bad))
		require.NotNil(t, v, bad)
		require.Equal(t, "placeholder-pin", v.Rule, bad)
	}
	require.Nil(t, checkAddedPins("app/src/main/res/values/strings.xml", "<resources/>", "<resources><pin>AAAA</pin></resources>"), "not a network security config")
}

func TestVerifyPatchRoutesPins(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/res/xml/network_security_config.xml": nscBase})
	v := verifyPatch(root, "app/src/main/res/xml/network_security_config.xml", nscBase,
		withPin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	require.NotNil(t, v)
	require.Equal(t, "placeholder-pin", v.Rule)
}
