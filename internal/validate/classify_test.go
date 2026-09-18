package validate

import "testing"

func TestLabelIsReserved(t *testing.T) {
	cases := []struct {
		label string
		want  bool
	}{
		{"", false},
		{"IANA 保留地址", true},
		{"局域网", true},
		{"PRIVATE ADDRESS", true},
		{"loopback", true},
		{"中国 北京 联通", false},
		{"美国 加利福尼亚", false},
	}
	for _, c := range cases {
		if got := labelIsReserved(c.label); got != c.want {
			t.Errorf("labelIsReserved(%q) = %v, want %v", c.label, got, c.want)
		}
	}
}

func TestCountryMatches(t *testing.T) {
	if !countryMatches("美国 Google", []string{"美国", "usa"}) {
		t.Fatal("should match US")
	}
	if !countryMatches("中国 福建省 厦门市", []string{"中国", "china"}) {
		t.Fatal("should match CN")
	}
	if countryMatches("中国", []string{"美国"}) {
		t.Fatal("should not match US")
	}
	if countryMatches("", []string{"美国"}) {
		t.Fatal("empty label must not match")
	}
}

func TestNormalizeCountry(t *testing.T) {
	if got := normalizeCountry("中国 广东省 深圳市 电信"); got != "中国" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeCountry("美国|加州|洛杉矶"); got != "美国" {
		t.Fatalf("got %q", got)
	}
}

func TestRegexDangerShapes(t *testing.T) {
	dangerous := []string{
		`(a+)+`,
		`(.*)*`,
		`(a|ab)+`,
		`([0-9]+)*\.example\.com`,
	}
	for _, p := range dangerous {
		if len(regexDanger(p)) == 0 {
			t.Errorf("expected dangerous shape flagged: %s", p)
		}
	}
	safe := []string{
		`.*\.example\.com`,
		`cdn-[0-9]+\.example\.net`,
		`foo\.bar`,
		`(a|b)\.static\.com`,
	}
	for _, p := range safe {
		if reasons := regexDanger(p); len(reasons) != 0 {
			t.Errorf("unexpected danger for %s: %v", p, reasons)
		}
	}
}

func TestRegexScore(t *testing.T) {
	simple := regexScore(`foo.bar`)
	complex := regexScore(`(([a-z]+[0-9]*){4,})+`)
	if complex <= simple {
		t.Fatalf("complexity score not ordered: %d vs %d", complex, simple)
	}
}

func TestLooksLikeDomain(t *testing.T) {
	if !looksLikeDomain("cdn.example.com") {
		t.Fatal("plain domain should pass")
	}
	if looksLikeDomain("not_a_domain") {
		t.Fatal("single label should fail")
	}
	if looksLikeDomain("bad domain.com") {
		t.Fatal("spaces should fail")
	}
}
