package db

import (
	"log"
	"os"

	"github.com/zu1k/nali/pkg/download"
	"github.com/zu1k/nali/pkg/zxipv6wry"
)

// ensureDBFile makes sure the active database file exists before a
// constructor opens it. When the file is missing the candidate is fetched
// and forced through the same validate-or-quarantine pipeline used by
// `nali update`, so unvalidated bytes can never reach query results through
// the constructor's implicit first-run download either.
//
// Formats without an auto-update source are left untouched; the constructor
// then surfaces the usual "file not found" error.
func ensureDBFile(d *DB) error {
	if _, err := os.Stat(d.File); err == nil {
		return nil
	}

	if len(d.DownloadUrls) > 0 {
		log.Printf("文件不存在，正在获取 %s 数据库...\n", d.Name)
		data, err := download.Fetch(d.DownloadUrls...)
		if err != nil {
			return err
		}
		return admitDownload(d, data)
	}

	if d.Format == FormatZXIPv6Wry {
		log.Println("文件不存在，正在获取最新 ZX IPv6数据库...")
		data, err := zxipv6wry.FetchData()
		if err != nil {
			return err
		}
		return admitDownload(d, data)
	}

	return nil
}
