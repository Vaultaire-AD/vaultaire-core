package response

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"strings"
)

type AttrContext struct {
	BaseDN string
	Groups []string
}

type AttrResolver func(user ldapstorage.User, ctx AttrContext) (string, bool)

var resolvers = map[string]AttrResolver{

	"uid": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Username, u.Username != ""
	},

	"cn": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Username, u.Username != ""
	},

	"mail": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		return u.Email, u.Email != ""
	},

	"displayname": func(u ldapstorage.User, _ AttrContext) (string, bool) {
		name := strings.TrimSpace(u.Firstname + " " + u.Lastname)
		return name, name != ""
	},

	"objectclass": func(_ ldapstorage.User, _ AttrContext) (string, bool) {
		return "inetOrgPerson", true
	},

	"memberof": func(_ ldapstorage.User, ctx AttrContext) (string, bool) {
		if len(ctx.Groups) == 0 {
			return "", false
		}
		return strings.Join(ctx.Groups, ","), true
	},
}
