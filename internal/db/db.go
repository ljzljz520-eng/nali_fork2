package db

import (
	"log"
	"net"

	"github.com/spf13/viper"

	"github.com/zu1k/nali/pkg/dbif"
)

func GetDB(typ dbif.QueryType) (db dbif.DB) {
	if db, found := dbTypeCache[typ]; found {
		return db
	}

	lang := viper.GetString("selected.lang")
	if lang == "" {
		lang = "zh-CN"
	}

	switch typ {
	case dbif.TypeIPv4:
		selected := viper.GetString("selected.ipv4")
		if selected == "" {
			if lang == "zh-CN" {
				selected = "qqwry"
			} else {
				selected = "geoip"
			}
		}
		db = getDbByName(selected).get()
	case dbif.TypeIPv6:
		selected := viper.GetString("selected.ipv6")
		if selected == "" {
			if lang == "zh-CN" {
				selected = "zxipv6wry"
			} else {
				selected = "geoip"
			}
		}
		db = getDbByName(selected).get()
	case dbif.TypeDomain:
		selected := viper.GetString("selected.cdn")
		if selected == "" {
			selected = "cdn"
		}
		db = getDbByName(selected).get()
	default:
		panic("Query type not supported!")
	}

	if db == nil {
		log.Fatalln("Database init failed")
	}

	dbTypeCache[typ] = db
	return
}

func Find(typ dbif.QueryType, query string) *Result {
	if result, found := queryCache.Load(query); found {
		return result.(*Result)
	}
	// Convert NAT64 64:ff9b::/96 to IPv4
	if typ == dbif.TypeIPv6 {
		ip := net.ParseIP(query)
		if ip != nil {
			_, NAT64, _ := net.ParseCIDR("64:ff9b::/96")
			if NAT64.Contains(ip) {
				ip4 := make(net.IP, 4)
				copy(ip4, ip[12:16])
				query = ip4.String()
				typ = dbif.TypeIPv4
			}
		}
	}
	db := GetDB(typ)
	result, err := db.Find(query)
	if err != nil {
		return nil
	}
	res := &Result{db.Name(), result}
	queryCache.Store(query, res)
	return res
}
