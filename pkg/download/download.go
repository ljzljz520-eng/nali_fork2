package download

import (
	"errors"
	"github.com/zu1k/nali/pkg/common"
)

// Fetch downloads database bytes into memory without touching the disk.
// Callers are expected to validate the content before it replaces the active
// database.
func Fetch(urls ...string) (data []byte, err error) {
	if len(urls) == 0 {
		return nil, errors.New("未指定下载 url")
	}
	return common.GetHttpClient().Get(urls...)
}

func Download(filePath string, urls ...string) (data []byte, err error) {
	data, err = Fetch(urls...)
	if err != nil {
		return
	}

	err = common.SaveFile(filePath, data)
	return
}
