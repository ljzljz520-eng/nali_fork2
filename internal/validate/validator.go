package validate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// Format identifiers mirror internal/db.Format; they are duplicated here to
// avoid an import cycle (internal/db imports this package).
const (
	FormatQQWry     = "qqwry"
	FormatZXIPv6Wry = "zxipv6wry"
	FormatIP2Region = "ip2region"
	FormatCDNYml    = "cdn-yml"
)

// ErrUnsupported means the format has no content validator; callers fall back
// to the legacy "format opens" check.
var ErrUnsupported = errors.New("no content validator for this format")

// Validate runs the full validation pipeline for a candidate database.
// activePath points at the database currently in use (may not exist yet);
// the returned Report is never nil when err is nil.
func Validate(dbName, format string, data []byte, activePath string, p Policy) (*Report, error) {
	sum := sha256sum(data)
	activeSum, oldData := activeFingerprint(activePath)

	r := newReport(dbName, format, activePath, int64(len(data)), sum, activeSum, p.EvidenceLimit)

	switch format {
	case FormatQQWry:
		validateWry[uint32](r, p, data, oldData, wryFamilyV4())
	case FormatZXIPv6Wry:
		validateWry[uint64](r, p, data, oldData, wryFamilyV6())
	case FormatIP2Region:
		validateIP2Region(r, p, data, oldData)
	case FormatCDNYml:
		validateCDN(r, p, data, oldData)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, format)
	}

	r.finalize()
	return r, nil
}

func sha256sum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func activeFingerprint(path string) (string, []byte) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}
	return sha256sum(data), data
}
