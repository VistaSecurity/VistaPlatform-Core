package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGenerationCheckRejectsDriftAndAcceptsRegeneration(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "gen-ratings")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	root := t.TempDir()
	run := func(check bool, wantSuccess bool) {
		t.Helper()
		args := []string{"--root", root}
		if check {
			args = append(args, "--check")
		}
		output, err := exec.Command(binary, args...).CombinedOutput()
		if (err == nil) != wantSuccess {
			t.Fatalf("check=%v success=%v: %v\n%s", check, wantSuccess, err, output)
		}
	}
	run(false, true)
	run(true, true)
	for _, file := range []string{"packages/primitives/src/ratings/definitions.gen.ts", "standards/generated/rating-definitions.json"} {
		path := filepath.Join(root, file)
		if err := os.WriteFile(path, []byte("forbidden drift"), 0644); err != nil {
			t.Fatal(err)
		}
		run(true, false)
		run(false, true)
		run(true, true)
	}
}
