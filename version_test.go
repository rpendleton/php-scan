package main

import "testing"

func TestVersionIn(t *testing.T) {
	for in, want := range map[string]string{
		"\x00X-Powered-By: PHP/8.3.6\x00":         "PHP 8.3.6",
		"\x00X-Powered-By: PHP/7.4.34-dev\x00":    "PHP 7.4.34-dev",
		"X-Powered-By: PHP/8.5.0RC1\x00more":      "PHP 8.5.0RC1",
		"X-Powered-By: PHP/\x00":                  "",
		"a binary that merely mentions PHP 8.3.6": "",
	} {
		if got := versionIn([]byte(in)); got != want {
			t.Errorf("versionIn(%q) = %q, want %q", in, got, want)
		}
	}
}
