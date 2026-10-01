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

// wikipedia-ios, 2026-10-01: the AppDelegate call declared
// `private func evaluateDeviceIntegrity()` at file scope and the SceneDelegate
// call called it -- "inaccessible due to 'private' protection level".
func TestCheckPrivateSwiftCalls(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}
	write("App/AppDelegate.swift", "import UIKit\n\nprivate func evaluateDeviceIntegrity() {}\n"+
		"fileprivate func probe() -> Bool { false }\nfunc sharedCheck() {}\n"+
		"final class Helper {\n    private func onlyHere() {}\n}\n")
	write("App/Other.swift", "final class Other {\n    private func twice() {}\n}\nfunc twice() {}\n")
	orig := "final class SceneDelegate {\n    func sceneDidBecomeActive() {\n        resume()\n    }\n    func resume() {}\n}\n"
	call := func(stmt string) string {
		return replaceOnce(t, orig, "        resume()\n", "        "+stmt+"\n        resume()\n")
	}
	path := "App/SceneDelegate.swift"

	for _, stmt := range []string{"evaluateDeviceIntegrity()", "if probe() { return }", "onlyHere()"} {
		v := checkPrivateSwiftCalls(root, path, orig, call(stmt))
		require.NotNil(t, v, stmt)
		require.Equal(t, "private-symbol", v.Rule, stmt)
		require.Contains(t, v.Detail, "AppDelegate.swift")
	}
	for _, stmt := range []string{
		"sharedCheck()",          // internal
		"twice()",                // one declaration is internal
		"getppid()",              // a C function declared nowhere here: not judged
		"resume()",               // declared in this file
		"if isatty(0) == 1 { }",  // lowercase C function: not judged
		"self.helper.onlyHere()", // member call through an instance: not a bare call
	} {
		require.Nil(t, checkPrivateSwiftCalls(root, path, orig, call(stmt)), stmt)
	}
	// Declared privately in the patched file itself: fine.
	selfDecl := call("localCheck()") + "private func localCheck() {}\n"
	require.Nil(t, checkPrivateSwiftCalls(root, path, orig, selfDecl))
}

// wikipedia-ios, 2026-10-01 (second run): the AppDelegate retry called
// evaluateDeviceIntegrity() and declared it nowhere -- "cannot find in scope".
func TestCheckUndeclaredSwiftCalls(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}
	write("App/Util.swift", "func sharedCheck() {}\n")
	write("App/VC.swift", "final class VC: UIViewController {\n    func go() { setNeedsLayout() }\n}\n")
	orig := "final class AppDelegate {\n    func launch() {\n        start()\n    }\n    func start() {}\n}\n"
	call := func(stmt string) string {
		return replaceOnce(t, orig, "        start()\n", "        "+stmt+"\n        start()\n")
	}
	path := "App/AppDelegate.swift"

	v := checkPrivateSwiftCalls(root, path, orig, call("evaluateDeviceIntegrity()"))
	require.NotNil(t, v)
	require.Equal(t, "undeclared-symbol", v.Rule)
	require.Contains(t, v.Detail, "evaluateDeviceIntegrity")

	for _, stmt := range []string{
		"sharedCheck()",                      // declared in another file
		"setNeedsLayout()",                   // called elsewhere: an inherited method
		"fatalError(\"x\")",                  // standard library
		"if stat(\"/bin/bash\", &s) == 0 {}", // lowercase C function: not judged
		"start()",                            // declared here
	} {
		require.Nil(t, checkPrivateSwiftCalls(root, path, orig, call(stmt)), stmt)
	}
	declaredHere := call("checkIntegrity()") + "func checkIntegrity() {}\n"
	require.Nil(t, checkPrivateSwiftCalls(root, path, orig, declaredHere))
}
