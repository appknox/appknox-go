package helper

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// Apple config checks. An Info.plist or .entitlements file is a property list:
// Xcode refuses a build whose plist does not parse, and a <dict> whose <key>s
// and values fall out of step reads as a different document. An .xcconfig is a
// list of build settings; an #include there pulls in a file nobody reviewed.

// checkPlist rejects a property-list patch that no longer parses as one: a
// <plist> root holding one value, every <dict> alternating <key> and exactly
// one value, no key twice in the same dict. A binary plist is refused outright
// -- the fixer edits text, and a binary plist edited as text is destroyed.
// Relative: when the original does not parse by this reader either, the patch
// is not judged.
func checkPlist(path, original, patched string) *patchViolation {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".plist", ".entitlements":
	default:
		return nil
	}
	if strings.HasPrefix(original, "bplist") {
		return &patchViolation{
			Rule: "binary-plist",
			Detail: fmt.Sprintf("%s is a binary property list, which cannot be edited as text. "+
				"Make no edit and report the setting the remediation asks for.", path),
		}
	}
	if parsePlist(original) != nil {
		return nil // this reader cannot read the file; do not judge the patch
	}
	if err := parsePlist(patched); err != nil {
		return &patchViolation{
			Rule: "malformed-plist",
			Detail: fmt.Sprintf("your edit leaves %s an invalid property list: %v. Inside <dict>, "+
				"every <key> is followed by exactly one value (<string>, <true/>, <false/>, "+
				"<integer>, <real>, <date>, <data>, <array>, <dict>), and no key appears twice.", path, err),
		}
	}
	return nil
}

// parsePlist validates an XML property list's structure.
func parsePlist(content string) error {
	dec := xml.NewDecoder(strings.NewReader(content))
	root, err := nextElement(dec)
	if err != nil {
		return err
	}
	start, ok := root.(xml.StartElement)
	if !ok || start.Name.Local != "plist" {
		return errors.New("the root element is not <plist>")
	}
	value, err := nextElement(dec)
	if err != nil {
		return err
	}
	v, ok := value.(xml.StartElement)
	if !ok {
		return errors.New("<plist> holds no value")
	}
	if err := parsePlistValue(dec, v); err != nil {
		return err
	}
	if end, err := nextElement(dec); err != nil {
		return err
	} else if _, ok := end.(xml.EndElement); !ok {
		return errors.New("<plist> holds more than one value")
	}
	if _, err := nextElement(dec); err != io.EOF {
		return errors.New("content after </plist>")
	}
	return nil
}

// parsePlistValue reads the value that start opens, through its end tag.
func parsePlistValue(dec *xml.Decoder, start xml.StartElement) error {
	switch name := start.Name.Local; name {
	case "dict":
		return parsePlistDict(dec)
	case "array":
		for {
			tok, err := nextElement(dec)
			if err != nil {
				return err
			}
			if _, ok := tok.(xml.EndElement); ok {
				return nil
			}
			if err := parsePlistValue(dec, tok.(xml.StartElement)); err != nil {
				return err
			}
		}
	case "string", "integer", "real", "date", "data":
		_, err := readText(dec)
		return err
	case "true", "false":
		tok, err := nextElement(dec)
		if err != nil {
			return err
		}
		if _, ok := tok.(xml.EndElement); !ok {
			return fmt.Errorf("<%s/> has content", name)
		}
		return nil
	default:
		return fmt.Errorf("<%s> is not a property-list value", name)
	}
}

// parsePlistDict reads <key>value pairs through </dict>.
func parsePlistDict(dec *xml.Decoder) error {
	seen := map[string]bool{}
	for {
		tok, err := nextElement(dec)
		if err != nil {
			return err
		}
		if _, ok := tok.(xml.EndElement); ok {
			return nil
		}
		key := tok.(xml.StartElement)
		if key.Name.Local != "key" {
			return fmt.Errorf("<%s> where a <key> belongs", key.Name.Local)
		}
		name, err := readText(dec)
		if err != nil {
			return err
		}
		if seen[name] {
			return fmt.Errorf("key %q appears twice in one <dict>", name)
		}
		seen[name] = true
		tok, err = nextElement(dec)
		if err != nil {
			return err
		}
		value, ok := tok.(xml.StartElement)
		if !ok || value.Name.Local == "key" {
			return fmt.Errorf("key %q has no value", name)
		}
		if err := parsePlistValue(dec, value); err != nil {
			return err
		}
	}
}

// nextElement returns the next start or end element, skipping whitespace,
// comments, the XML declaration and the DOCTYPE. Text between elements is an
// error: a value's text belongs inside its tags.
func nextElement(dec *xml.Decoder) (xml.Token, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement, xml.EndElement:
			return xml.CopyToken(t), nil
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return nil, fmt.Errorf("stray text %q", strings.TrimSpace(string(t)))
			}
		}
	}
}

// readText reads a text-only element's content through its end tag.
func readText(dec *xml.Decoder) (string, error) {
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			b.Write(t)
		case xml.EndElement:
			return b.String(), nil
		case xml.StartElement:
			return "", fmt.Errorf("<%s> inside a text value", t.Name.Local)
		}
	}
}

// xcconfigSettingRE is one build setting: NAME, optional [cond=value] qualifiers, =, value.
var xcconfigSettingRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*(\[[^\]=]+=[^\]]*\])*\s*=`)

// checkXcconfig holds an .xcconfig patch to build settings and // comments:
// an added #include pulls in a file nobody reviewed, and anything else is not
// a setting Xcode reads.
func checkXcconfig(path, original, patched string) *patchViolation {
	if !strings.EqualFold(filepath.Ext(path), ".xcconfig") {
		return nil
	}
	for _, line := range rawAddedLines(original, patched) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || xcconfigSettingRE.MatchString(t) {
			continue
		}
		return &patchViolation{
			Rule: "xcconfig-edit",
			Detail: fmt.Sprintf("your edit to %s adds %q, which is not a build setting (NAME = value). "+
				"Change or add only the settings the remediation names; never add an #include.", path, t),
		}
	}
	return nil
}
