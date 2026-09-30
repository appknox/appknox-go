package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A fix must not add logging: the scanner raises new log calls as Application
// Logs (PeopleInSpace: the exported-receiver fix added two Log.w calls and the
// rescan reported finding 17 introduced).
func TestCheckAddedLogging(t *testing.T) {
	kt := "app/src/main/java/com/x/R1.kt"
	java := "app/src/main/java/com/x/J.java"
	cases := []struct {
		name, path, original, patched string
		want                          bool
	}{
		{"kotlin Log.w added", kt, "class A {\n}\n",
			"import android.util.Log\nclass A {\n  fun f() { Log.w(\"T\", \"x\") }\n}\n", true},
		{"java Log.d added", java, "class J {}\n", "class J { void f() { Log.d(\"T\", \"x\"); } }\n", true},
		{"qualified android.util.Log", java, "class J {}\n", "class J { void f() { android.util.Log.e(\"T\", \"x\"); } }\n", true},
		{"printStackTrace added", java, "class J {}\n", "class J { void f(Exception e) { e.printStackTrace(); } }\n", true},
		{"System.out added", java, "class J {}\n", "class J { void f() { System.out.println(\"x\"); } }\n", true},
		{"println added in kotlin", kt, "class A\n", "class A { fun f() { println(\"x\") } }\n", true},
		{"Timber added", kt, "class A\n", "class A { fun f() { Timber.i(\"x\") } }\n", true},
		{"one more of an existing call", kt,
			"class A { fun f() { Log.w(\"T\", \"a\") } }\n",
			"class A { fun f() { Log.w(\"T\", \"a\"); Log.w(\"T\", \"b\") } }\n", true},
		{"existing call kept", kt,
			"class A { fun f() { Log.w(\"T\", \"a\") } }\n",
			"class A { fun f() { Log.w(\"T\", \"a\"); val y = 1 } }\n", false},
		{"logging removed", kt, "class A { fun f() { Log.d(\"T\", \"a\") } }\n", "class A { fun f() { } }\n", false},
		{"in a comment", kt, "class A\n", "class A { // Log.d(\"T\", \"x\")\n}\n", false},
		{"in a string", kt, "class A\n", "class A { val s = \"Log.d(x)\" }\n", false},
		{"xml ignored", "app/src/main/AndroidManifest.xml", "<manifest/>", "<manifest><!-- Log.d( --></manifest>", false},
		{"catalog not a logger", kt, "class A\n", "class A { val c = Catalog.d(1) }\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := checkAddedLogging(c.path, c.original, c.patched)
			if !c.want {
				require.Nil(t, v)
				return
			}
			require.NotNil(t, v)
			require.Equal(t, "adds-logging", v.Rule)
		})
	}
}
