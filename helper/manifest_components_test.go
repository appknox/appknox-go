package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	appOpen  = "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n  <application>\n"
	appClose = "  </application>\n</manifest>\n"
	mainAct  = "    <activity android:name=\".Main\"><intent-filter>" +
		"<action android:name=\"android.intent.action.MAIN\"/></intent-filter></activity>\n"
	imeFilter = "<intent-filter><action android:name=\"android.view.InputMethod\"/></intent-filter>"
)

func withApp(components ...string) string {
	out := appOpen
	for _, c := range components {
		out += c
	}
	return out + appClose
}

func TestManifestComponents(t *testing.T) {
	got := manifestComponents(withApp(mainAct,
		"    <service android:name=\".Sync\" android:exported=\"false\"/>\n"))
	require.Equal(t, []manifestComponent{
		{Tag: "activity", Name: ".Main", HasFilter: true},
		{Tag: "service", Name: ".Sync", HasExported: true},
	}, got)
}

func TestCheckExported(t *testing.T) {
	p := "app/src/main/AndroidManifest.xml"
	orig := withApp(mainAct)
	svc := func(attrs, body string) string {
		return "    <service android:name=\".SecureIME\"" + attrs + ">" + body + "</service>\n"
	}

	v := checkExported(p, orig, withApp(mainAct, svc("", imeFilter)))
	require.NotNil(t, v)
	require.Equal(t, "exported-missing", v.Rule)
	require.Contains(t, v.Detail, ".SecureIME")
	require.Contains(t, v.Detail, "android:exported")

	require.Nil(t, checkExported(p, orig, withApp(mainAct, svc(" android:exported=\"true\"", imeFilter))))
	require.Nil(t, checkExported(p, orig, withApp(mainAct, svc("", ""))), "no filter: exported defaults safely")
	require.Nil(t, checkExported(p, orig, withApp(mainAct)+"\n"), "a pre-existing component is not this patch's doing")
	require.Nil(t, checkExported("app/src/main/res/xml/a.xml", orig, withApp(svc("", imeFilter))))

	gains := checkExported(p, withApp(svc("", "")), withApp(svc("", imeFilter)))
	require.NotNil(t, gains, "an existing component gaining its first filter needs exported too")
}

func TestVerifyPatchRejectsExportedMissing(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: withApp(mainAct)})
	patched := withApp(mainAct, "    <service android:name=\".SecureIME\">"+imeFilter+"</service>\n")
	v := verifyPatch(root, manifestRel, withApp(mainAct), patched)
	require.NotNil(t, v)
	require.Equal(t, "exported-missing", v.Rule)
}
