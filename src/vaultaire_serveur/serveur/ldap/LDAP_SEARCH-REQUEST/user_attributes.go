package ldapsearchrequest

import (
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
	"strings"
)

type AttrContext struct {
	BaseDN string
	Groups []string
}

type AttrResolver func(user ldapstorage.User, ctx AttrContext) (string, bool)

var userAttributeResolvers = map[string]AttrResolver{

	"uid": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Username, u.Username != ""
	},

	"samaccountname": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Username, u.Username != ""
	},

	"mail": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Email, u.Email != ""
	},

	"displayname": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		name := strings.TrimSpace(u.Firstname + " " + u.Lastname)
		return name, name != ""
	},

	"entryuuid": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Username, true
	},
	"nsuniqueid": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Username, true
	},
	"objectguid": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Username, true
	},
	"guid": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Username, true
	},
	"ipauniqueid": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Username, true
	},

	"memberof": func(_ ldapstorage.User, ctx AttrContext) (string, bool) {
		if len(ctx.Groups) == 0 {
			return "", false
		}
		return strings.Join(ctx.Groups, ","), true
	},
}
