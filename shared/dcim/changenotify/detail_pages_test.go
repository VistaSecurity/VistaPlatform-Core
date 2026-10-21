package changenotify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A notification's link must be a page the web UI actually routes: a link the
// router does not know 404s, which is worse than the honest null. Every entry
// in detailPages has to be a `<Route path="<prefix>:id">` in frontend-v2's
// App.tsx. Mutation: add a kind with a made-up prefix to detailPages → red.
func TestDetailPagesAreRoutesTheWebUIServes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "frontend-v2", "src", "App.tsx"))
	if err != nil {
		t.Fatalf("read App.tsx: %v", err)
	}
	app := string(raw)
	for kind, prefix := range detailPages {
		if route := `path="` + prefix + `:id"`; !strings.Contains(app, route) {
			t.Errorf("%s links to %s<id>, but App.tsx has no %s route", kind, prefix, route)
		}
	}
}
