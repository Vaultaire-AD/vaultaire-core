package serviceauth

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Codes de trame.
const (
	TrameAuth          = "08_01"
	TrameAuthOK        = "08_02"
	TrameAuthFailed    = "08_03"
	TrameRefresh       = "08_04"
	TrameRefreshOK     = "08_05"
	TrameRefreshDenied = "08_06"
)

// Codes d'erreur de 08_03 et 08_06. Le service les traduit pour son
// utilisateur ; la raison qui les accompagne est destinée au journal.
const (
	CodeBadCredentials    = "bad_credentials"     // compte inconnu OU mot de passe faux
	CodeExpired           = "expired"             // mot de passe expiré
	CodeMFARequired       = "mfa_required"        // second facteur actif, otp: absent
	CodeMFAInvalid        = "mfa_invalid"         // code faux ou déjà consommé
	CodeMFAEnrollRequired = "mfa_enroll_required" // imposé mais pas encore posé
	CodeLocked            = "locked"              // limitation de débit
	CodeRevoked           = "revoked"             // kill switch
	CodeDenied            = "denied"              // pas de droit de connexion au domaine
	CodeDeleted           = "deleted"             // compte supprimé (08_06)
	CodeUnknown           = "unknown"             // compte jamais présenté par ce service (08_06)
	CodeUnavailable       = "unavailable"         // base illisible, erreur interne
	CodeInvalidRequest    = "invalid_request"     // trame malformée
)

// TTL conseillé au service avant de relire un compte (08_04).
const ttlSecondes = 300

// Bornes : un service n'a aucune raison d'envoyer plus.
const (
	maxLigne      = 512
	maxMotDePasse = 1024
)

var (
	// refRe borne l'identifiant de corrélation : il est renvoyé tel quel et
	// finit dans les journaux du service.
	refRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	// identRe : nom de compte, éventuellement suivi de @domaine. Les noms du
	// core sont déjà contraints à la création ; on refuse ici tout ce qui
	// n'en a pas la forme, avant d'interroger la base.
	identRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}(@[A-Za-z0-9.-]{1,253})?$`)
)

// Demande est une trame 08_01 ou 08_04 analysée.
type Demande struct {
	Ref         string
	Identifiant string // tel que saisi : « alice » ou « alice@infra.acme.lan »
	MotDePasse  string // 08_01 seulement
	OTP         string
	From        string
}

// champs lit les lignes « clé:valeur ». Une clé répétée garde la première
// valeur : la suivante ne peut pas écraser ce qu'un contrôle a déjà lu.
func champs(lignes []string) map[string]string {
	m := map[string]string{}
	for _, l := range lignes {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, deja := m[k]; !deja {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// AnalyserAuth lit le contenu d'une 08_01 :
//
//	<identifiant>
//	<mot de passe>
//	otp:<code>        facultatif
//	from:<adresse>    facultatif
//	ref:<id>          facultatif
//
// Le mot de passe est pris TEL QUEL — espaces compris — et c'est la seule
// ligne qui ne soit pas préfixée : il peut contenir « : ».
func AnalyserAuth(contenu string) (Demande, string) {
	lignes := strings.Split(contenu, "\n")
	if len(lignes) < 2 {
		return Demande{}, "identifiant et mot de passe attendus"
	}
	d := Demande{
		Identifiant: strings.TrimSpace(lignes[0]),
		MotDePasse:  strings.TrimSuffix(lignes[1], "\r"),
	}
	f := champs(lignes[2:])
	d.OTP, d.From, d.Ref = f["otp"], f["from"], f["ref"]
	return d, d.valider(true)
}

// AnalyserRefresh lit le contenu d'une 08_04 : « ref: » et « user: ».
func AnalyserRefresh(contenu string) (Demande, string) {
	f := champs(strings.Split(contenu, "\n"))
	d := Demande{Identifiant: f["user"], Ref: f["ref"]}
	return d, d.valider(false)
}

func (d Demande) valider(avecMotDePasse bool) string {
	if d.Ref != "" && !refRe.MatchString(d.Ref) {
		return "ref: invalide"
	}
	if !identRe.MatchString(d.Identifiant) {
		return "identifiant invalide"
	}
	if avecMotDePasse && (d.MotDePasse == "" || len(d.MotDePasse) > maxMotDePasse) {
		return "mot de passe vide ou trop long"
	}
	if len(d.OTP) > 16 || len(d.From) > maxLigne {
		return "champ trop long"
	}
	return ""
}

// Identite est ce que le core rend d'un compte vérifié.
type Identite struct {
	User   string   // nom canonique du compte
	Name   string   // nom affiché
	Groups []string // « groupe@domaine »
	Rights []string // clés RBAC accordées, filtrées par le catalogue
}

// lignePropre retire ce qui casserait la trame : un saut de ligne dans un nom
// affiché décalerait tous les champs suivants.
func lignePropre(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	if len(s) > maxLigne {
		s = s[:maxLigne]
	}
	return strings.TrimSpace(s)
}

// contenuOK compose le contenu de 08_02 / 08_05.
func contenuOK(ref string, id Identite) []string {
	groups := append([]string(nil), id.Groups...)
	sort.Strings(groups)
	rights := append([]string(nil), id.Rights...)
	sort.Strings(rights)
	for i := range groups {
		groups[i] = strings.ReplaceAll(lignePropre(groups[i]), ",", "")
	}
	return []string{
		"ref:" + ref,
		"user:" + lignePropre(id.User),
		"name:" + lignePropre(id.Name),
		"groups:" + strings.Join(groups, ","),
		"rights:" + strings.Join(rights, ","),
		"ttl:" + strconv.Itoa(ttlSecondes),
	}
}

// contenuErreur compose le contenu de 08_03 / 08_06.
func contenuErreur(ref, code, raison string) []string {
	return []string{"ref:" + ref, "code:" + code, "reason:" + lignePropre(raison)}
}
