package validate

import "testing"

const healthyCDNYaml = `
example.com:
  name: Example
  link: https://example.com
"(cdn|static).example.net":
  name: Example CDN
  link: https://example.net
files.example.org:
  name: Example Files
  link: https://example.org
`

func runCDN(t *testing.T, data, old []byte, p Policy) *Report {
	t.Helper()
	r := newReport("cdn", FormatCDNYml, "cdn.yml", int64(len(data)), "x", "", p.EvidenceLimit)
	validateCDN(r, p, data, old)
	r.finalize()
	return r
}

func TestValidateCDNHealthy(t *testing.T) {
	r := runCDN(t, []byte(healthyCDNYaml), nil, DefaultPolicy())
	if r.Quarantined() {
		for _, c := range r.Checks {
			if c.Level == LevelFail {
				t.Logf("FAIL %s: %s", c.Name, c.Detail)
			}
		}
		t.Fatal("healthy cdn.yml should pass")
	}
}

func TestValidateCDNInvalidYAML(t *testing.T) {
	r := runCDN(t, []byte("a: b: c: ["), nil, DefaultPolicy())
	if !r.Quarantined() || !hasCheck(r, "format", LevelFail) {
		t.Fatal("malformed yaml should fail format check")
	}
}

func TestValidateCDNInvalidRegex(t *testing.T) {
	bad := healthyCDNYaml + `
"(unclosed":
  name: Broken
  link: ""
`
	r := runCDN(t, []byte(bad), nil, DefaultPolicy())
	if !r.Quarantined() || !hasCheck(r, "regex-compile", LevelFail) {
		t.Fatal("invalid regex should fail regex-compile check")
	}
	if !evidenceKind(r, "cdn-invalid-regex") {
		t.Fatal("missing invalid regex evidence")
	}
}

func TestValidateCDNDangerousRegex(t *testing.T) {
	bad := healthyCDNYaml + `
"(a+)+.example.com":
  name: Evil
  link: ""
`
	r := runCDN(t, []byte(bad), nil, DefaultPolicy())
	if !r.Quarantined() || !hasCheck(r, "regex-complexity", LevelFail) {
		t.Fatal("catastrophic-backtracking shape should fail")
	}
	if !evidenceKind(r, "cdn-regex-dangerous-shape") {
		t.Fatal("missing dangerous shape evidence")
	}
}

func TestValidateCDNHighChangeRate(t *testing.T) {
	old := []byte(`
a.example.com: {name: A, link: ""}
b.example.com: {name: B, link: ""}
c.example.com: {name: C, link: ""}
d.example.com: {name: D, link: ""}
`)
	// only one of four survives
	newData := []byte(`
a.example.com: {name: A, link: ""}
brand-new.example.io: {name: N, link: ""}
`)
	r := runCDN(t, newData, old, DefaultPolicy())
	if !hasCheck(r, "diff-current", LevelFail) {
		t.Fatal("removing 3/4 entries should exceed change threshold")
	}
}

func TestValidateCDNEmptyName(t *testing.T) {
	bad := []byte(`
example.com:
  name: ""
  link: ""
`)
	r := runCDN(t, []byte(bad), nil, DefaultPolicy())
	if !r.Quarantined() || !hasCheck(r, "entry-integrity", LevelFail) {
		t.Fatal("empty CDN name should fail entry integrity")
	}
}
