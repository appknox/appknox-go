package helper

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// loggingCallRE finds a logging call in Java or Kotlin code: android.util.Log
// and Timber levels, printStackTrace and System.out/err.
var loggingCallRE = regexp.MustCompile(
	`\b(?:(?:android\.util\.)?Log|Timber)\.(?:v|d|i|w|e|wtf)\s*\(` +
		`|\.printStackTrace\s*\(` +
		`|\bSystem\.(?:out|err)\.print`)

// kotlinPrintRE finds Kotlin's top-level println/print, which write to stdout.
var kotlinPrintRE = regexp.MustCompile(`(?:^|[^\w.])print(?:ln)?\s*\(`)

// swiftLogRE finds a Swift logging call: print, debugPrint, dump, NSLog,
// os_log, and a Logger/os.Logger level method.
var swiftLogRE = regexp.MustCompile(
	`(?:^|[^\w.])(?:print|debugPrint|dump|NSLog|os_log)\s*\(` +
		`|\b(?:[lL]ogger|log)\.(?:trace|debug|info|notice|warning|error|critical|fault|log)\s*\(`)

// checkAddedLogging rejects a Java/Kotlin/Swift patch that adds a logging call. No
// remediation asks for one, and the scanner raises new log calls as the
// Application Logs finding, so a fix that logs trades one finding for another.
// It counts calls rather than diffing lines: one more Log.w than the original
// had is an addition even when an identical call already exists.
func checkAddedLogging(path, original, patched string) *patchViolation {
	ext := strings.ToLower(filepath.Ext(path))
	var res []*regexp.Regexp
	switch ext {
	case ".java":
		res = []*regexp.Regexp{loggingCallRE}
	case ".kt":
		res = []*regexp.Regexp{loggingCallRE, kotlinPrintRE}
	case ".swift":
		res = []*regexp.Regexp{swiftLogRE}
	default:
		return nil
	}
	kotlin := ext == ".kt"
	before, after := codeOnly(original, kotlin), codeOnly(patched, kotlin)
	for _, re := range res {
		added := len(re.FindAllString(after, -1)) - len(re.FindAllString(before, -1))
		if added <= 0 {
			continue
		}
		call := strings.TrimLeft(re.FindString(after), " \t\n({;=,")
		return &patchViolation{
			Rule: "adds-logging",
			Detail: fmt.Sprintf("%s adds %d logging call(s) (%s...). The scanner reports new logging as "+
				"Application Logs, so the fix would introduce a finding. Handle the case without logging: "+
				"return early, ignore the input, or throw.", path, added, call),
		}
	}
	return nil
}
