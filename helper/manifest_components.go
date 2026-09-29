package helper

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"
)

// manifestComponent is one <activity|activity-alias|service|receiver|provider>.
type manifestComponent struct {
	Tag, Name              string
	HasFilter, HasExported bool
}

var componentTags = map[string]bool{
	"activity": true, "activity-alias": true, "service": true, "receiver": true, "provider": true,
}

// manifestComponents lists the components a manifest declares, in order. A
// manifest that stops parsing yields what was read before the error: the
// well-formedness check has already judged it.
func manifestComponents(src string) []manifestComponent {
	var out []manifestComponent
	current, depth, compDepth := -1, 0, 0
	dec := xml.NewDecoder(strings.NewReader(src))
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case current < 0 && componentTags[t.Name.Local]:
				c := manifestComponent{Tag: t.Name.Local}
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "name":
						c.Name = a.Value
					case "exported":
						c.HasExported = true
					}
				}
				out = append(out, c)
				current, compDepth = len(out)-1, depth
			case current >= 0 && t.Name.Local == "intent-filter":
				out[current].HasFilter = true
			}
		case xml.EndElement:
			if current >= 0 && depth == compDepth {
				current = -1
			}
			depth--
		}
	}
}

// checkExported rejects a component the patch adds, or gives its first
// <intent-filter>, without android:exported: from Android 12 the manifest
// merger refuses it (vuln-bank-mobile's SecureInputMethodService).
func checkExported(path, original, patched string) *patchViolation {
	if filepath.Base(path) != "AndroidManifest.xml" {
		return nil
	}
	before := map[string]manifestComponent{}
	for _, c := range manifestComponents(original) {
		before[c.Tag+" "+c.Name] = c
	}
	for _, c := range manifestComponents(patched) {
		prev, existed := before[c.Tag+" "+c.Name]
		if c.HasExported || !c.HasFilter || (existed && prev.HasFilter) {
			continue
		}
		return &patchViolation{
			Rule: "exported-missing",
			Detail: fmt.Sprintf("%s declares <%s android:name=\"%s\"> with an <intent-filter> but no "+
				"android:exported, which the manifest merger refuses. Add android:exported=\"false\" unless "+
				"other apps or the system must reach it; a system-bound service (an input method, an "+
				"accessibility service) needs android:exported=\"true\" and its binding permission.",
				path, c.Tag, c.Name),
		}
	}
	return nil
}
