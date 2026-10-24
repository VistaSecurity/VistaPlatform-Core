package agentlogs

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClampLines(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, DefaultLines}, {-5, DefaultLines}, {1, 1}, {200, 200}, {MaxLines, MaxLines}, {MaxLines + 1, MaxLines},
	} {
		if got := ClampLines(tc.in); got != tc.want {
			t.Errorf("ClampLines(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// The point of the second pass: a line carrying a credential must not reach
// the console, whichever side cleaned it.
func TestCleanRedactsCredentials(t *testing.T) {
	lines := Clean([]string{
		`connecting to https://admin:hunter2@fw.example.net/api`,
		`login failed: {"username":"svc","password":"S3cret!"}`,
		`Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def`,
		`interrogation of 10.0.0.1 completed in 3s`,
	}, 10)
	joined := strings.Join(lines, "\n")
	for _, secret := range []string{"hunter2", "S3cret!", "eyJhbGciOiJIUzI1NiJ9"} {
		if strings.Contains(joined, secret) {
			t.Errorf("secret %q survived Clean:\n%s", secret, joined)
		}
	}
	if lines[3] != `interrogation of 10.0.0.1 completed in 3s` {
		t.Errorf("an innocent line was changed: %q", lines[3])
	}
}

func TestCleanKeepsTheNewestLines(t *testing.T) {
	var in []string
	for i := 0; i < 50; i++ {
		in = append(in, fmt.Sprintf("line %d", i))
	}
	out := Clean(in, 5)
	if len(out) != 5 || out[0] != "line 45" || out[4] != "line 49" {
		t.Fatalf("Clean(50 lines, 5) = %v, want lines 45..49", out)
	}
}

func TestCleanCutsLongLinesOnARuneBoundary(t *testing.T) {
	long := strings.Repeat("é", MaxLineBytes) // two bytes each
	out := Clean([]string{long}, 1)[0]
	if !strings.HasSuffix(out, truncatedMark) {
		t.Fatalf("a long line was not marked as truncated")
	}
	if len(out) > MaxLineBytes+len(truncatedMark) {
		t.Fatalf("cut line is %d bytes, want at most %d", len(out), MaxLineBytes+len(truncatedMark))
	}
	if !utf8.ValidString(out) {
		t.Fatalf("the cut split a UTF-8 sequence")
	}
}

func TestRing(t *testing.T) {
	r := NewRing(3)
	_, _ = r.Write([]byte("a\nb\n"))
	_, _ = r.Write([]byte("c\n\nd\n"))
	if got := strings.Join(r.Tail(0), ","); got != "b,c,d" {
		t.Fatalf("Tail(0) = %q, want b,c,d", got)
	}
	if got := strings.Join(r.Tail(2), ","); got != "c,d" {
		t.Fatalf("Tail(2) = %q, want c,d", got)
	}
	// A copy: changing it must not change the buffer.
	tail := r.Tail(1)
	tail[0] = "x"
	if r.Tail(1)[0] != "d" {
		t.Fatal("Tail returned the buffer's own slice")
	}
}
