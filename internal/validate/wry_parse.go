package validate

import (
	"errors"

	"github.com/zu1k/nali/pkg/wry"
)

// maxWryRedirects bounds the redirect chain (mode 0x01/0x02) followed while
// decoding one record. A corrupt file can otherwise loop forever.
const maxWryRedirects = 8

// parseWryRecord decodes one qqwry/zxipv6wry record with strict bounds
// checking. It mirrors pkg/wry/parse.go but never panics on corrupt bytes and
// refuses pathological redirect chains.
//
// start is the absolute offset of the mode byte (caller already applies the
// qqwry +4 adjustment).
func parseWryRecord(data []byte, start uint32) (wry.Result, error) {
	pos := start
	country, area := "", ""

	// Follow the leading mode-1 redirect chain (country pointer).
	for hop := 0; ; hop++ {
		if hop > maxWryRedirects {
			return wry.Result{}, errors.New("redirect chain too long")
		}
		mode, err := readByte(data, pos)
		if err != nil {
			return wry.Result{}, err
		}
		switch mode {
		case wry.RedirectMode1:
			next, err := readOffset3(data, pos+1)
			if err != nil {
				return wry.Result{}, err
			}
			pos = next
		case wry.RedirectMode2:
			// [0x02][absolute offset of country][area...]
			countryOff, err := readOffset3(data, pos+1)
			if err != nil {
				return wry.Result{}, err
			}
			country, err = readCString(data, countryOff)
			if err != nil {
				return wry.Result{}, err
			}
			area, err = readArea(data, pos+4)
			if err != nil {
				return wry.Result{}, err
			}
			return wry.Result{Country: country, Area: area}, nil
		default:
			// Inline country string, then area.
			var err error
			country, pos, err = readCStringAdvance(data, pos)
			if err != nil {
				return wry.Result{}, err
			}
			area, err = readArea(data, pos)
			if err != nil {
				return wry.Result{}, err
			}
			return wry.Result{Country: country, Area: area}, nil
		}
	}
}

// readArea decodes the area field at pos: a pointer (mode 1/2) or inline string.
func readArea(data []byte, pos uint32) (string, error) {
	mode, err := readByte(data, pos)
	if err != nil {
		return "", err
	}
	if mode == wry.RedirectMode1 || mode == wry.RedirectMode2 {
		off, err := readOffset3(data, pos+1)
		if err != nil {
			return "", err
		}
		if off == 0 {
			return "", nil
		}
		return readCString(data, off)
	}
	s, _, err := readCStringAdvance(data, pos)
	return s, err
}

func readByte(data []byte, pos uint32) (byte, error) {
	if int(pos) >= len(data) {
		return 0, errors.New("read out of range")
	}
	return data[pos], nil
}

func readOffset3(data []byte, pos uint32) (uint32, error) {
	if uint64(pos)+3 > uint64(len(data)) {
		return 0, errors.New("offset out of range")
	}
	return wry.Bytes3ToUint32(data[pos : pos+3]), nil
}

func readCString(data []byte, pos uint32) (string, error) {
	s, _, err := readCStringAdvance(data, pos)
	return s, err
}

// readCStringAdvance returns the NUL-terminated string at pos plus the offset
// right after the trailing NUL.
func readCStringAdvance(data []byte, pos uint32) (string, uint32, error) {
	if int(pos) >= len(data) {
		return "", 0, errors.New("string out of range")
	}
	for i := int(pos); i < len(data); i++ {
		if data[i] == 0 {
			return string(data[pos:i]), uint32(i + 1), nil
		}
	}
	return "", 0, errors.New("unterminated string")
}
