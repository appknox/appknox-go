package helper

import (
	"strings"
	"testing"
)

func TestCheckSecrets_RefusesAddedCredentials(t *testing.T) {
	original := "class A {\n}\n"
	for _, added := range []string{
		`String k = "AKIAABCDEFGHIJKLMNOP";`,
		`String k = "AIzaSyA1234567890abcdefghijklmnopqrstuv";`,
		`// token ghp_abcdefghijklmnopqrstuvwxyz0123456789`,
		`-----BEGIN RSA PRIVATE KEY-----`,
		`private static final String API_KEY = "s3cr3t-value-123";`,
		`val password = "hunter2hunter2"`,
	} {
		patched := "class A {\n" + added + "\n}\n"
		v := checkSecrets("app/A.java", original, patched)
		if v == nil {
			t.Errorf("checkSecrets accepted %q", added)
			continue
		}
		if v.Rule != "secret-in-edit" {
			t.Errorf("rule = %q, want secret-in-edit", v.Rule)
		}
		// The report goes back to the model: it must not repeat the secret.
		if strings.Contains(v.Detail, strings.Trim(added, " ")) {
			t.Errorf("detail repeats the secret: %q", v.Detail)
		}
	}
}

func TestCheckSecrets_IgnoresSecretsAlreadyThereAndOrdinaryCode(t *testing.T) {
	existing := `String k = "AKIAABCDEFGHIJKLMNOP";` + "\n"
	if v := checkSecrets("app/A.java", existing, existing+"int x = 1;\n"); v != nil {
		t.Errorf("blamed the patch for an existing key: %v", v)
	}
	for _, code := range []string{
		`Cipher c = Cipher.getInstance("AES/GCM/NoPadding");`,
		`String password = readPasswordFromKeystore();`,
		`if (token == null) return;`,
	} {
		if v := checkSecrets("app/A.java", "", code); v != nil {
			t.Errorf("checkSecrets refused ordinary code %q: %v", code, v)
		}
	}
}
