package updates

import "testing"

func TestNotesURL(t *testing.T) {
	cases := []struct{ registry, version, base, want string }{
		{"ghcr.io", "4.6.0", "", "https://github.com/VistaSecurity/VistaPlatform-Core/releases/tag/v4.6.0"},
		{"GHCR.IO", "4.6.0", "https://ignored/", "https://github.com/VistaSecurity/VistaPlatform-Core/releases/tag/v4.6.0"},
		{"docker.io", "4.6.0", "", "https://vistasecurity.io/docs/releases/4.6.0/"},
		{"mirror.example:5000", "4.6.0", "https://docs.example/releases", "https://docs.example/releases/4.6.0/"},
		{"docker.io", "4.6.0-rc.1", "https://docs.example/r/", "https://docs.example/r/4.6.0-rc.1/"},
	}
	for _, c := range cases {
		if got := NotesURL(c.registry, c.version, c.base); got != c.want {
			t.Errorf("NotesURL(%q,%q,%q) = %q, want %q", c.registry, c.version, c.base, got, c.want)
		}
	}
}
