package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const swiftVC = `import UIKit
import Alamofire

final class TransportViewController: UIViewController {
    // print("debug {")
    let apiKey = "abc{"

    func send() {
        print("sending")
        AF.request("https://example.com")
    }
}
`

func TestBraceBalanceSwift(t *testing.T) {
	patched := replaceOnce(t, swiftVC, "        AF.request(\"https://example.com\")\n    }\n", "        AF.request(\"https://example.com\")\n")
	v := checkBraceBalance("DVIA/TransportViewController.swift", swiftVC, patched)
	require.NotNil(t, v)
	require.Equal(t, "unbalanced-braces", v.Rule)
	require.Nil(t, checkBraceBalance("DVIA/TransportViewController.swift", swiftVC,
		replaceOnce(t, swiftVC, `let apiKey = "abc{"`, `let apiKey = ""`)))
}

func TestCheckAddedLoggingSwift(t *testing.T) {
	for name, call := range map[string]string{
		"print": `print("key removed")`, "debugPrint": `debugPrint(x)`, "NSLog": `NSLog("x")`,
		"os_log": `os_log("x")`, "Logger": `logger.debug("x")`, "dump": `dump(x)`,
	} {
		patched := replaceOnce(t, swiftVC, "        AF.request", "        "+call+"\n        AF.request")
		v := checkAddedLogging("DVIA/TransportViewController.swift", swiftVC, patched)
		require.NotNil(t, v, name)
		require.Equal(t, "adds-logging", v.Rule, name)
	}
	// Removing a print is fine; a print in a comment or string is not a call.
	require.Nil(t, checkAddedLogging("DVIA/TransportViewController.swift", swiftVC,
		replaceOnce(t, swiftVC, "        print(\"sending\")\n", "")))
	require.Nil(t, checkAddedLogging("DVIA/TransportViewController.swift", swiftVC,
		replaceOnce(t, swiftVC, `let apiKey = "abc{"`, `let note = "print(x)" // NSLog("y")`)))
}

func swiftRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}
	write("DVIA/TransportViewController.swift", swiftVC)
	write("DVIA/Other.swift", "import SwiftyJSON\n")
	write("Podfile", "target 'DVIA' do\n  pod 'KeychainSwift'\nend\n")
	write("Pods/Evil/Evil.swift", "import EvilKit\n")
	return root
}

func TestCheckSwiftImports(t *testing.T) {
	root := swiftRepo(t)
	path := "DVIA/TransportViewController.swift"
	for _, module := range []string{"Security", "CryptoKit", "LocalAuthentication", "SwiftyJSON", "KeychainSwift"} {
		patched := replaceOnce(t, swiftVC, "import Alamofire\n", "import Alamofire\nimport "+module+"\n")
		require.Nil(t, checkSwiftImports(root, path, swiftVC, patched), module)
	}
	for _, module := range []string{"KeychainAccess", "EvilKit"} {
		patched := replaceOnce(t, swiftVC, "import Alamofire\n", "import Alamofire\nimport "+module+"\n")
		v := checkSwiftImports(root, path, swiftVC, patched)
		require.NotNil(t, v, module)
		require.Equal(t, "missing-library", v.Rule, module)
		require.Contains(t, v.Detail, module)
	}
	require.Nil(t, checkSwiftImports(root, path, swiftVC, swiftVC), "an existing import is not judged")
}

// The gate routes Swift through the import check.
func TestVerifyPatchRoutesSwift(t *testing.T) {
	root := swiftRepo(t)
	patched := replaceOnce(t, swiftVC, "import Alamofire\n", "import Alamofire\nimport KeychainAccess\n")
	v := verifyPatchWith(root, "DVIA/TransportViewController.swift", swiftVC, patched, gateOpts{})
	require.NotNil(t, v)
	require.Equal(t, "missing-library", v.Rule)
}
