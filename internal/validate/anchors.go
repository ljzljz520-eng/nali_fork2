package validate

// reservedV4 are the IPv4 special-purpose prefixes registered in RFC 6890
// (plus the shared CGN range from RFC 6598). A trustworthy geo-IP database
// must not assign a geographic/ISP location to addresses from these ranges.
var reservedV4 = []struct {
	cidr    string
	purpose string
	probe   string // address actually queried
}{
	{"0.0.0.0/8", "本网络/当前网络 RFC1122", "0.1.2.3"},
	{"10.0.0.0/8", "私有地址 RFC1918", "10.0.0.1"},
	{"100.64.0.0/10", "运营商级共享地址 RFC6598", "100.64.0.1"},
	{"127.0.0.0/8", "环回地址 RFC1122", "127.0.0.1"},
	{"169.254.0.0/16", "链路本地地址 RFC3927", "169.254.1.1"},
	{"172.16.0.0/12", "私有地址 RFC1918", "172.16.0.1"},
	{"192.0.0.0/24", "IETF 协议分配 RFC6890", "192.0.0.1"},
	{"192.0.2.0/24", "文档示例 TEST-NET-1 RFC5737", "192.0.2.1"},
	{"192.88.99.0/24", "6to4 中继任播 RFC3068", "192.88.99.1"},
	{"192.168.0.0/16", "私有地址 RFC1918", "192.168.1.1"},
	{"198.18.0.0/15", "网络基准测试 RFC2544", "198.18.0.1"},
	{"198.51.100.0/24", "文档示例 TEST-NET-2 RFC5737", "198.51.100.1"},
	{"203.0.113.0/24", "文档示例 TEST-NET-3 RFC5737", "203.0.113.1"},
	{"224.0.0.0/4", "组播地址 RFC3171", "224.0.0.1"},
	{"240.0.0.0/4", "保留地址 RFC1112", "240.0.0.1"},
	{"255.255.255.255/32", "有限广播地址 RFC919", "255.255.255.255"},
}

// reservedV6 are IPv6 special-purpose prefixes (RFC 4291 / RFC 4048 / RFC 3849 ...).
var reservedV6 = []struct {
	cidr    string
	purpose string
	probe   string
}{
	{"::/128", "未指定地址 RFC4291", "::"},
	{"::1/128", "环回地址 RFC4291", "::1"},
	{"::ffff:0:0/96", "IPv4 映射地址 RFC4291", "::ffff:0.1.2.3"},
	{"64:ff9b::/96", "NAT64 前缀 RFC6052", "64:ff9b::1"},
	{"100::/64", "仅丢弃前缀 RFC6666", "100::1"},
	{"2001:db8::/32", "文档示例 RFC3849", "2001:db8::1"},
	{"2001:10::/28", "ORCHID RFC4843", "2001:10::1"},
	{"fc00::/7", "唯一本地地址 RFC4193", "fc00::1"},
	{"fe80::/10", "链路本地地址 RFC4291", "fe80::1"},
	{"ff00::/8", "组播地址 RFC4291", "ff00::1"},
}

// anchor is a well-known anycast/service address with a stable country.
// Empty labels are tolerated (sparse DBs); a non-empty but contradictory
// label is counted as mismatch.
type anchor struct {
	ip      string
	country string // human readable
	tokens  []string
	v6      bool
}

var anchorsV4 = []anchor{
	{"8.8.8.8", "美国 Google Public DNS", []string{"美国", "united states", "usa"}, false},
	{"8.8.4.4", "美国 Google Public DNS", []string{"美国", "united states", "usa"}, false},
	{"208.67.222.222", "美国 OpenDNS", []string{"美国", "united states", "usa"}, false},
	{"223.5.5.5", "中国 阿里 DNS", []string{"中国", "china", "cn", "中华"}, false},
	{"223.6.6.6", "中国 阿里 DNS", []string{"中国", "china", "cn", "中华"}, false},
	{"114.114.114.114", "中国 114DNS", []string{"中国", "china", "cn", "中华"}, false},
	{"119.29.29.29", "中国 DNSPod", []string{"中国", "china", "cn", "中华"}, false},
	{"180.76.76.76", "中国 百度 DNS", []string{"中国", "china", "cn", "中华"}, false},
}

var anchorsV6 = []anchor{
	{"2001:4860:4860::8888", "美国 Google", []string{"美国", "united states", "usa"}, true},
	{"2001:4860:4860::8844", "美国 Google", []string{"美国", "united states", "usa"}, true},
	{"2400:3200::1", "中国 阿里 DNS", []string{"中国", "china", "cn", "中华"}, true},
	{"2400:da00::6666", "中国 阿里 DNS", []string{"中国", "china", "cn", "中华"}, true},
}

// reservedMarkers are label fragments that indicate the database knows the
// address is special rather than geographic.
var reservedMarkers = []string{
	"IANA", "RFC", "保留", "内网", "私有", "局域", "本机", "环回",
	"本地", "未分配", "多播", "组播", "广播", "测试", "文档",
	"RESERVED", "PRIVATE", "LOOPBACK", "LINK-LOCAL", "MULTICAST",
	"BROADCAST", "UNSPECIFIED", "DOCUMENTATION", "TEST-NET", "CGN",
	"SHARED", "CARRIER-GRADE", "BENCHMARK", "ORCHID", "丢弃",
}

// labelIsReserved reports whether the (already normalized) label explicitly
// marks an address as special-purpose.
func labelIsReserved(label string) bool {
	if label == "" {
		return false
	}
	upper := toUpperASCII(label)
	for _, m := range reservedMarkers {
		if containsFold(upper, toUpperASCII(m)) {
			return true
		}
	}
	return false
}

// countryMatches checks whether the label contains any expected country token.
func countryMatches(label string, tokens []string) bool {
	if label == "" {
		return false
	}
	upper := toUpperASCII(label)
	for _, t := range tokens {
		if containsFold(upper, toUpperASCII(t)) {
			return true
		}
	}
	return false
}

func toUpperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// containsFold is an ASCII-case-insensitive substring test; CJK tokens pass
// through byte comparison unchanged.
func containsFold(upperHaystack, upperNeedle string) bool {
	if len(upperNeedle) == 0 {
		return false
	}
	return indexOf(upperHaystack, upperNeedle) >= 0
}

func indexOf(s, sub string) int {
	n, m := len(s), len(sub)
	if m > n {
		return -1
	}
	for i := 0; i+m <= n; i++ {
		if s[i:i+m] == sub {
			return i
		}
	}
	return -1
}

// normalizeCountry extracts the leading country/region token of a label.
// "中国 广东省 深圳市 电信" -> "中国"; "美国|加利福尼亚|..." -> "美国".
func normalizeCountry(label string) string {
	out := make([]rune, 0, len(label))
	for _, r := range label {
		if r == ' ' || r == '\t' || r == '|' || r == '　' {
			break
		}
		out = append(out, r)
	}
	return string(out)
}
