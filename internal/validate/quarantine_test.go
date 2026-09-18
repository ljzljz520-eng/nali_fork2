package validate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineStoreListActivate(t *testing.T) {
	rootDirOverride = t.TempDir()
	defer func() { rootDirOverride = "" }()

	payload := []byte("FAKE-DB-CONTENT")
	r := newReport("qqwry", FormatQQWry, "qqwry.dat", int64(len(payload)),
		sha256sum(payload), "", 10)
	r.addCheck(Check{Name: "invariants", Level: LevelFail, Detail: "synthetic failure"})
	r.addEvidence(Evidence{Kind: "overlap-or-unsorted", Target: "1.2.3.4"})

	dir, err := Store(r, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "qqwry.dat")); err != nil {
		t.Fatalf("payload missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "report.json")); err != nil {
		t.Fatalf("report missing: %v", err)
	}

	all, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(all["qqwry"]) != 1 {
		t.Fatalf("expected one snapshot, got %d", len(all["qqwry"]))
	}

	e, err := LatestEntry("qqwry")
	if err != nil {
		t.Fatal(err)
	}
	if e.Report == nil || !e.Report.Quarantined() {
		t.Fatal("report should indicate quarantine")
	}
	if len(e.Report.Evidence) != 1 {
		t.Fatalf("evidence = %d", len(e.Report.Evidence))
	}

	target := filepath.Join(t.TempDir(), "active", "qqwry.dat")
	if err := Activate(e, target); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("activated payload mismatch")
	}
}

func TestQuarantineActivateChecksumGuard(t *testing.T) {
	rootDirOverride = t.TempDir()
	defer func() { rootDirOverride = "" }()

	payload := []byte("ANOTHER-FAKE")
	r := newReport("cdn", FormatCDNYml, "cdn.yml", int64(len(payload)),
		sha256sum(payload), "", 10)
	r.addCheck(Check{Name: "regex-compile", Level: LevelFail})
	dir, err := Store(r, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the quarantined payload: activation must refuse it.
	payloadPath := filepath.Join(dir, "cdn.yml")
	if err := os.WriteFile(payloadPath, []byte("TAMPERED"), 0644); err != nil {
		t.Fatal(err)
	}
	e, err := GetEntry("cdn", "")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "cdn.yml")
	if err := Activate(e, target); err == nil {
		t.Fatal("checksum mismatch should block activation")
	}
}
