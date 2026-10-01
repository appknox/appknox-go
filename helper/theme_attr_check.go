package helper

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// themeAttrRE finds an unprefixed theme-attribute reference in XML: ?attr/name
// or ?name. ?android:attr/name and ?android:name never match (':' is not part
// of the name and "android" would have to be followed by '/').
var themeAttrRE = regexp.MustCompile(`"\?(?:attr/)?([A-Za-z][A-Za-z0-9_]*)"`)

// xmlCommentRE matches an XML comment.
var xmlCommentRE = regexp.MustCompile(`(?s)<!--.*?-->`)

// libraryThemeAttrs are AppCompat/Material theme attributes an app may use
// unprefixed. Not exhaustive: an attribute missing here costs one fixer retry
// toward ?android:attr/, never a broken build.
var libraryThemeAttrs = map[string]bool{
	"colorPrimary": true, "colorPrimaryDark": true, "colorPrimaryVariant": true, "colorAccent": true,
	"colorSecondary": true, "colorSecondaryVariant": true, "colorTertiary": true, "colorSurface": true,
	"colorSurfaceVariant": true, "colorError": true, "colorOutline": true,
	"colorControlNormal": true, "colorControlActivated": true, "colorControlHighlight": true,
	"colorButtonNormal": true, "actionBarSize": true, "actionBarTheme": true,
	"selectableItemBackground": true, "selectableItemBackgroundBorderless": true,
	"dividerHorizontal": true, "dividerVertical": true, "listPreferredItemHeight": true,
	"homeAsUpIndicator": true, "toolbarStyle": true,
}

// libraryThemeAttrPrefixes cover the families too large to list.
var libraryThemeAttrPrefixes = []string{"colorOn", "textAppearance", "materialButton", "materialCard",
	"shapeAppearance", "actionMode", "actionBar", "bottomNavigation", "floatingActionButton"}

// checkThemeAttrs rejects an XML patch that adds an unprefixed theme attribute
// (?attr/x) the app cannot resolve: neither declared by the repository nor a
// known AppCompat/Material attribute. Framework attributes need the android:
// prefix; resource linking fails on "?attr/colorBackground" with "resource
// attr/colorBackground not found". Never deferred: completing it would define
// an attribute no theme sets, which links but fails at inflation.
func checkThemeAttrs(root, path, original, patched string) *patchViolation {
	if strings.ToLower(filepath.Ext(path)) != ".xml" {
		return nil
	}
	had := map[string]bool{}
	for _, m := range themeAttrRE.FindAllStringSubmatch(xmlCommentRE.ReplaceAllString(original, ""), -1) {
		had[m[1]] = true
	}
	var idx *resourceIndex
	for _, m := range themeAttrRE.FindAllStringSubmatch(xmlCommentRE.ReplaceAllString(patched, ""), -1) {
		name := m[1]
		if had[name] || libraryThemeAttr(name) {
			continue
		}
		if idx == nil {
			idx = buildResourceIndex(root)
		}
		if idx.has("attr", name) {
			continue
		}
		return &patchViolation{
			Rule: "unresolved-theme-attr",
			Detail: fmt.Sprintf("%s adds ?attr/%s, but this app declares no attribute %s and it is not an "+
				"AppCompat/Material attribute. For a framework attribute write ?android:attr/%s; otherwise "+
				"use a literal value or an existing resource.", path, name, name, name),
		}
	}
	return nil
}

func libraryThemeAttr(name string) bool {
	if libraryThemeAttrs[name] {
		return true
	}
	for _, p := range libraryThemeAttrPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
