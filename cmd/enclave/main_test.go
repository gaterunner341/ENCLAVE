package main

import (
	"bytes"
	"flag"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// capture runs a command with a scratch data directory and returns what it
// printed, so that the documented command lines are covered rather than
// assumed.
func capture(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	prev := stdout
	stdout = &buf
	defer func() { stdout = prev }()
	err := run(append(args, "--data", dir))
	return buf.String(), err
}

func TestFlagsAreReadWhereverTheyAppear(t *testing.T) {
	cases := [][]string{
		{"findings", "--data", "d", "--enclave", "CORE"},
		{"--data", "d", "findings", "--enclave", "CORE"},
		{"--data=d", "--enclave=CORE", "findings"},
		{"findings", "--data", "d", "--enclave=CORE"},
	}
	for _, args := range cases {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		dir := fs.String("data", "", "")
		enc := fs.String("enclave", "", "")
		rest, err := parseFlags(fs, args)
		if err != nil {
			t.Errorf("%v: %v", args, err)
			continue
		}
		if *dir != "d" || *enc != "CORE" {
			t.Errorf("%v gave data=%q enclave=%q", args, *dir, *enc)
		}
		if len(rest) != 1 || rest[0] != "findings" {
			t.Errorf("%v left positional %v", args, rest)
		}
	}

	// A boolean flag must not swallow the argument after it.
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	place := fs.Bool("place-by-address", false, "")
	rest, err := parseFlags(fs, []string{"--place-by-address", "a.ckl", "b.ckl"})
	if err != nil {
		t.Fatal(err)
	}
	if !*place || strings.Join(rest, " ") != "a.ckl b.ckl" {
		t.Errorf("bool flag handling wrong: place=%v rest=%v", *place, rest)
	}
}

func TestDocumentedCommandsWork(t *testing.T) {
	dir := t.TempDir()

	out, err := capture(t, dir, "enclave", "add", "--id", "CORE", "--name", "Core Operations",
		"--cidr", "10.20.0.0/16", "--baseline", "nist-800-53r5:moderate")
	if err != nil {
		t.Fatalf("enclave add: %v", err)
	}
	if !strings.Contains(out, "created enclave CORE") {
		t.Errorf("enclave add said %q", out)
	}

	if _, err := capture(t, dir, "enclave", "add", "--id", "MGMT", "--name", "Management",
		"--cidr", "10.20.9.0/24", "--baseline", "cis-controls-v8:ig2"); err != nil {
		t.Fatalf("second enclave: %v", err)
	}

	out, err = capture(t, dir, "enclave", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "CORE") || !strings.Contains(out, "MGMT") {
		t.Errorf("enclave list said %q", out)
	}

	ckl := filepath.Join("..", "..", "testdata", "sample.ckl")
	nessus := filepath.Join("..", "..", "testdata", "sample.nessus")
	out, err = capture(t, dir, "import", "--enclave", "CORE", "--by", "P. Kittelson", ckl)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !strings.Contains(out, "3 findings added") {
		t.Errorf("import said %q", out)
	}

	// Placing by address has to route the management VLAN host to MGMT.
	if _, err := capture(t, dir, "import", "--enclave", "CORE", "--place-by-address", nessus); err != nil {
		t.Fatalf("import with placement: %v", err)
	}

	// Every documented export has to produce rows, not just a header. The flags
	// come after the positional argument here on purpose: that is how the
	// documentation shows it, and it is the shape that used to be silently
	// ignored.
	for _, kind := range []string{"findings", "baseline", "assets", "risks"} {
		out, err := capture(t, dir, "export", kind)
		if err != nil {
			t.Errorf("export %s: %v", kind, err)
			continue
		}
		lines := strings.Count(strings.TrimSpace(out), "\n")
		if kind == "risks" {
			// Nothing has been added to the register, so a header alone is right.
			if lines != 0 {
				t.Errorf("export risks produced %d rows with an empty register", lines)
			}
			continue
		}
		if lines < 1 {
			t.Errorf("export %s produced only a header:\n%s", kind, out)
		}
	}

	// Scoping an export to one enclave has to change the result.
	all, _ := capture(t, dir, "export", "findings")
	one, _ := capture(t, dir, "export", "findings", "--enclave", "MGMT")
	if len(one) >= len(all) {
		t.Error("--enclave did not narrow the export")
	}
	if !strings.Contains(one, "Management") {
		t.Error("the management enclave's findings are missing, so placement by address did not work")
	}

	if _, err := capture(t, dir, "export", "nonsense"); err == nil {
		t.Error("an unknown export kind should be an error")
	}

	out, err = capture(t, dir, "version")
	if err != nil || !strings.Contains(out, "ENCLAVE") {
		t.Errorf("version said %q, %v", out, err)
	}

	if err := run([]string{"nonsense-command"}); err == nil {
		t.Error("an unknown command should be an error")
	}
}

func TestImportRefusesWithoutAnEnclave(t *testing.T) {
	dir := t.TempDir()
	if _, err := capture(t, dir, "import", filepath.Join("..", "..", "testdata", "sample.ckl")); err == nil {
		t.Error("importing without --enclave should be refused")
	}
	if _, err := capture(t, dir, "import", "--enclave", "NOPE",
		filepath.Join("..", "..", "testdata", "sample.ckl")); err == nil {
		t.Error("importing into an unknown enclave should be refused")
	}
}

func TestDataDirectoryResolution(t *testing.T) {
	dir := t.TempDir()
	got, err := dataDir(dir)
	if err != nil || got != dir {
		t.Errorf("an explicit directory should win: %q %v", got, err)
	}
	t.Setenv("ENCLAVE_DATA", dir)
	got, err = dataDir("")
	if err != nil || got != dir {
		t.Errorf("ENCLAVE_DATA should be used when no flag is given: %q %v", got, err)
	}
	t.Setenv("ENCLAVE_DATA", "")
	got, err = dataDir("")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "enclave-data" {
		t.Errorf("the default should sit beside the executable, got %q", got)
	}
}

func TestLoopbackDetection(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": true, "localhost:8080": true, "[::1]:8080": true,
		"0.0.0.0:8080": false, "10.0.0.5:8080": false, "": false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
	if got := displayAddr("0.0.0.0:8080"); got != "127.0.0.1:8080" {
		t.Errorf("a wildcard bind should print a reachable address, got %q", got)
	}
}

func TestBadBaselineIsRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := capture(t, dir, "enclave", "add", "--id", "X", "--name", "X",
		"--baseline", "no-such-catalog"); err == nil {
		t.Error("an unknown catalog should be rejected rather than stored")
	}
	if _, err := capture(t, dir, "enclave", "add", "--id", "X"); err == nil {
		t.Error("--name should be required")
	}
}
