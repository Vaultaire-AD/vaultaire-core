package serviceauth

import (
	"strings"
	"sync"
	"time"

	"vaultaire/core/auth/passwordpolicy"
	"vaultaire/core/auth/ratelimit"
	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	dbldap "vaultaire/core/database/db_ldap"
	dbusers "vaultaire/core/database/db_users"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/global/security/totp"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

// depsDB branche la vérification sur les fonctions que les autres portes
// utilisent déjà. Chaque ligne en nomme une : c'est ce qui garantit que la
// catégorie 08 applique les mêmes règles que le portail, LDAP et 03_01.
func depsDB() Deps {
	return Deps{
		RateAllow: ratelimit.Autorise,
		RateFail:  ratelimit.Echec,
		RateOK:    ratelimit.Reussite,
		UserID: func(user string) (int, error) {
			return dbusers.Get_User_ID_By_Username(database.GetDatabase(), user)
		},
		CheckPassword: func(id int, mdp string) (bool, error) {
			return dbusers.VerifierMotDePasse(database.GetDatabase(), id, mdp)
		},
		IsRevoked:          permission.IsRevoked,
		EstCompteDAmorcage: isprotected.IsProtectedUser,
		PasswordExpired: func(user string) (bool, error) {
			st, err := passwordpolicy.Check(database.GetDatabase(), user)
			return st.IsExpired(), err
		},
		MFAState: func(user string) (bool, string, bool, error) {
			db := database.GetDatabase()
			state, err := dbauthpolicy.GetAuthState(db, user)
			if err != nil {
				return false, "", false, err
			}
			// IsMFARequired est fail-closed : en cas d'erreur elle répond
			// « exigé ». On suit sa réponse, comme le portail.
			exige, errR := dbauthpolicy.IsMFARequired(db, user)
			if errR != nil {
				logs.Write_LogCode("ERROR", logs.CodeDBQuery,
					"service auth: exigence MFA illisible pour "+user+" : "+errR.Error())
			}
			return state.MFAEnabled, state.MFASecret, exige, nil
		},
		ValidateTOTP: totp.Validate,
		ConsumeCounter: func(user string, c int64) (bool, error) {
			return dbauthpolicy.ConsumeMFACounter(database.GetDatabase(), user, c)
		},
		CanConnect: peutSeConnecter,
		GroupIDs:   permission.GetGroupIDsForUser,
		HasAction:  permission.HasActionAnywhere,
		Groups: func(user string) ([]string, error) {
			gs, err := dbldap.GetMemberOfByUsername(database.GetDatabase(), user)
			if err != nil {
				return nil, err
			}
			vus := map[string]bool{}
			var out []string
			for _, g := range gs {
				v := g.GroupName + "@" + g.DomainName
				if !vus[v] {
					vus[v] = true
					out = append(out, v)
				}
			}
			return out, nil
		},
		Name: func(user string) string {
			info, err := dbusers.Command_GET_UserInfo(database.GetDatabase(), user)
			if err != nil || info == nil {
				return ""
			}
			return strings.TrimSpace(info.Firstname + " " + info.Lastname)
		},
		Log: func(niveau, message string) {
			if niveau == "SECURITY" || niveau == "WARNING" {
				logs.Write_LogCode(niveau, logs.CodeAuthFailed, message)
				return
			}
			logs.Write_Log(niveau, message)
		},
		Now: time.Now,
	}
}

// peutSeConnecter applique la permission « auth ».
//
// Un agent présente toujours « compte@domaine » (03_01). Un service, lui,
// reçoit ce que l'utilisateur a tapé, le plus souvent le nom seul.
// CanUserConnectToDomain refuse un login sans domaine — aucun domaine à
// évaluer —, on essaie donc chacun des DOMAINES PRINCIPAUX du compte (les seuls
// valides pour une connexion) : un seul suffit, comme pour une lecture.
func peutSeConnecter(login string) (bool, string) {
	if strings.Contains(login, "@") {
		return permission.CanUserConnectToDomain(login)
	}
	principaux, err := permission.DomainesDeConnexion(login)
	if err != nil {
		return false, "compte inconnu ou domaines illisibles"
	}
	raison := "le compte n'appartient à aucun domaine"
	for _, d := range principaux {
		ok, r := permission.CanUserConnectToDomain(login + "@" + d)
		if ok {
			return true, ""
		}
		raison = r
	}
	return false, raison
}

var (
	defaut     *Manager
	defautOnce sync.Once
)

// Trame_Manager est l'entrée du répartiteur (trames_manager/Spliter.go).
func Trame_Manager(t storage.Trames_struct_client, s *storage.DuckySession) string {
	defautOnce.Do(func() { defaut = NewManager(depsDB()) })
	return defaut.Traiter(t, s)
}
