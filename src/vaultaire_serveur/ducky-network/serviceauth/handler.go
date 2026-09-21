package serviceauth

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"vaultaire/core/clienttype"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/trame"
)

// Deps est ce que la vérification attend du reste du core.
//
// Injecté pour que l'ordre des contrôles — la partie qui compte — se teste sans
// base. Voir depsDB pour le branchement réel : chaque champ y appelle la
// fonction déjà utilisée par le portail, le bind LDAP ou 03_01. Aucune règle
// n'est réécrite ici.
type Deps struct {
	// Limitation des tentatives, compteurs partagés avec les autres portes.
	RateAllow func(compte, source string) (bool, time.Duration)
	RateFail  func(compte, source string)
	RateOK    func(compte, source string)

	UserID        func(user string) (int, error)
	CheckPassword func(id int, motDePasse string) (bool, error)
	IsRevoked     func(user string) bool
	// PasswordExpired : une erreur de lecture n'empêche pas la connexion
	// (même règle que passwordpolicy.Check).
	PasswordExpired func(user string) (bool, error)
	// MFAState : second facteur posé (secret non vide) et exigé par un groupe.
	MFAState       func(user string) (enabled bool, secret string, required bool, err error)
	ValidateTOTP   func(secret, code string, now time.Time) (int64, bool)
	ConsumeCounter func(user string, counter int64) (bool, error)
	// CanConnect : permission « auth » sur le domaine du compte.
	CanConnect func(login string) (bool, string)
	GroupIDs   func(user string) ([]int, error)
	HasAction  func(groupIDs []int, key string) bool
	Groups     func(user string) ([]string, error) // « groupe@domaine »
	Name       func(user string) string

	Log func(niveau, message string)
	Now func() time.Time
}

// Manager traite une trame de catégorie 08. Il rend la réponse à envoyer, ou
// une chaîne vide.
type Manager struct {
	deps Deps

	mu        sync.Mutex
	vus       map[string]map[string]time.Time // service → compte → dernière vérification
	retention time.Duration
}

// NewManager crée un gestionnaire.
func NewManager(d Deps) *Manager {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = func(string, string) {}
	}
	return &Manager{deps: d, vus: map[string]map[string]time.Time{}, retention: 24 * time.Hour}
}

// maxComptesParService borne la mémoire des comptes présentés.
const maxComptesParService = 20000

// Traiter est le point d'entrée appelé par le répartiteur.
func (m *Manager) Traiter(t storage.Trames_struct_client, s *storage.DuckySession) string {
	if len(t.Message_Order) < 2 {
		return ""
	}
	typ := ""
	service := t.ClientSoftwareID
	if s != nil {
		typ, service = s.BoundClientType, s.BoundClientSoftwareID
	}
	// Défense en profondeur : le répartiteur a déjà vérifié que ce type peut
	// émettre la trame. Un type qui ne serait pas un service n'a de toute façon
	// rien à faire ici.
	if !clienttype.IsService(typ) || service == "" {
		m.deps.Log("SECURITY", fmt.Sprintf("service auth: trame %s_%s d'un client non service (%q, type %q)",
			t.Message_Order[0], t.Message_Order[1], service, typ))
		return ""
	}
	switch t.Message_Order[1] {
	case "01":
		code, contenu := m.authentifier(service, typ, t.Content)
		return trame.ReponseClient(code, t.Destination_Server, t.SessionIntegritykey, contenu...)
	case "04":
		code, contenu := m.relire(service, typ, t.Content)
		return trame.ReponseClient(code, t.Destination_Server, t.SessionIntegritykey, contenu...)
	default:
		m.deps.Log("WARNING", "service auth: sous-trame 08_"+t.Message_Order[1]+" non gérée")
		return ""
	}
}

func (m *Manager) authentifier(service, typ, contenu string) (string, []string) {
	d, erreur := AnalyserAuth(contenu)
	refus := func(code, raison string) (string, []string) {
		return TrameAuthFailed, contenuErreur(d.Ref, code, raison)
	}
	if erreur != "" {
		m.deps.Log("WARNING", "service auth: 08_01 malformée de "+service+" : "+erreur)
		return refus(CodeInvalidRequest, erreur)
	}
	user, _, _ := strings.Cut(d.Identifiant, "@")
	journal := func(niveau, quoi string) {
		m.deps.Log(niveau, fmt.Sprintf("service auth: %s user=%s service=%s from=%s", quoi, user, service, orTiret(d.From)))
	}

	// 1. LIMITATION — avant tout, y compris avant de savoir si le compte existe.
	// La source est le service : ses utilisateurs finaux ne sont pas identifiables
	// de façon sûre, et une adresse « from: » est déclarative.
	if ok, reste := m.deps.RateAllow(user, service); !ok {
		journal("SECURITY", "refusé, trop de tentatives (encore "+reste.Round(time.Second).String()+")")
		return refus(CodeLocked, "trop de tentatives")
	}

	// 2. COMPTE INCONNU — même refus qu'un mauvais mot de passe.
	id, err := m.deps.UserID(user)
	if err != nil {
		m.deps.RateFail(user, service)
		journal("WARNING", "refusé, compte inconnu")
		return refus(CodeBadCredentials, "identifiants invalides")
	}

	// 3. MOT DE PASSE — une panne de lecture n'est pas un échec compté.
	valide, err := m.deps.CheckPassword(id, d.MotDePasse)
	if err != nil {
		journal("ERROR", "mot de passe illisible : "+err.Error())
		return refus(CodeUnavailable, "vérification impossible")
	}
	if !valide {
		m.deps.RateFail(user, service)
		journal("WARNING", "refusé, mot de passe incorrect")
		return refus(CodeBadCredentials, "identifiants invalides")
	}

	// À partir d'ici, qui lit la réponse connaît déjà le mot de passe : les
	// refus peuvent être explicites.

	// 4. RÉVOCATION.
	if m.deps.IsRevoked(user) {
		journal("SECURITY", "refusé, compte révoqué")
		return refus(CodeRevoked, "compte révoqué")
	}

	// 5. EXPIRATION.
	if expire, err := m.deps.PasswordExpired(user); err != nil {
		journal("ERROR", "état d'expiration illisible ("+err.Error()+") — vérification poursuivie")
	} else if expire {
		journal("SECURITY", "refusé, mot de passe expiré")
		return refus(CodeExpired, "mot de passe expiré")
	}

	// 6. SECOND FACTEUR — obligatoire dès qu'il est posé. Contrairement au bind
	// LDAP, ce canal sait le porter : aucun réglage ne le rend facultatif.
	actif, secret, exige, err := m.deps.MFAState(user)
	if err != nil {
		journal("ERROR", "état du second facteur illisible : "+err.Error())
		return refus(CodeUnavailable, "vérification impossible")
	}
	switch {
	case actif && secret != "":
		if d.OTP == "" {
			journal("INFO", "second facteur demandé")
			return refus(CodeMFARequired, "code du second facteur requis")
		}
		compteur, ok := m.deps.ValidateTOTP(secret, d.OTP, m.deps.Now())
		if !ok {
			m.deps.RateFail(user, service)
			journal("WARNING", "refusé, code de second facteur invalide")
			return refus(CodeMFAInvalid, "code invalide")
		}
		// ANTI-REJEU : un code observé ne sert qu'une fois, sur toutes les
		// portes — le compteur est celui du portail.
		consomme, err := m.deps.ConsumeCounter(user, compteur)
		if err != nil {
			journal("ERROR", "compteur du second facteur illisible : "+err.Error())
			return refus(CodeUnavailable, "vérification impossible")
		}
		if !consomme {
			m.deps.RateFail(user, service)
			journal("SECURITY", "refusé, code de second facteur rejoué")
			return refus(CodeMFAInvalid, "code déjà utilisé")
		}
	case exige:
		journal("SECURITY", "refusé, second facteur imposé mais non enrôlé")
		return refus(CodeMFAEnrollRequired, "second facteur à enrôler sur le portail")
	}

	// 7. DROIT DE CONNEXION au domaine (permission « auth »).
	if ok, raison := m.deps.CanConnect(d.Identifiant); !ok || user == "vaultaire" {
		if user == "vaultaire" {
			raison = "compte d'amorçage réservé au core"
		}
		journal("WARNING", "refusé, "+raison)
		return refus(CodeDenied, "accès refusé")
	}

	// 8. IDENTITÉ ET DROITS.
	idt, err := m.identite(user, typ)
	if err != nil {
		journal("ERROR", "identité illisible : "+err.Error())
		return refus(CodeUnavailable, "vérification impossible")
	}

	m.deps.RateOK(user, service)
	m.retenir(service, user)
	journal("INFO", fmt.Sprintf("succès (%d groupe(s), droits: %s)", len(idt.Groups), orTiret(strings.Join(idt.Rights, ","))))
	return TrameAuthOK, contenuOK(d.Ref, idt)
}

func (m *Manager) relire(service, typ, contenu string) (string, []string) {
	d, erreur := AnalyserRefresh(contenu)
	refus := func(code, raison string) (string, []string) {
		return TrameRefreshDenied, contenuErreur(d.Ref, code, raison)
	}
	if erreur != "" {
		return refus(CodeInvalidRequest, erreur)
	}
	user, _, _ := strings.Cut(d.Identifiant, "@")

	// Un service ne relit que les comptes qu'il a lui-même vérifiés : sans ce
	// contrôle, un service compromis énumérerait les droits de tout l'annuaire.
	if !m.aVu(service, user) {
		m.deps.Log("SECURITY", "service auth: 08_04 sur un compte jamais présenté user="+user+" service="+service)
		return refus(CodeUnknown, "compte non vérifié par ce service")
	}
	if _, err := m.deps.UserID(user); err != nil {
		m.oublier(service, user)
		return refus(CodeDeleted, "compte supprimé")
	}
	if m.deps.IsRevoked(user) {
		return refus(CodeRevoked, "compte révoqué")
	}
	if expire, err := m.deps.PasswordExpired(user); err == nil && expire {
		return refus(CodeExpired, "mot de passe expiré")
	}
	if ok, _ := m.deps.CanConnect(d.Identifiant); !ok {
		return refus(CodeDenied, "accès refusé")
	}
	idt, err := m.identite(user, typ)
	if err != nil {
		// Le service garde ses droits précédents : une panne passagère ne doit
		// pas déconnecter tout le monde. Il ne reçoit pas de refus, seulement
		// l'indisponibilité, et réessaiera.
		return refus(CodeUnavailable, "relecture impossible")
	}
	m.retenir(service, user)
	return TrameRefreshOK, contenuOK(d.Ref, idt)
}

// identite lit les groupes et les clés du compte, filtrées par le catalogue.
func (m *Manager) identite(user, typ string) (Identite, error) {
	groupes, err := m.deps.Groups(user)
	if err != nil {
		return Identite{}, err
	}
	ids, err := m.deps.GroupIDs(user)
	if err != nil {
		return Identite{}, err
	}
	var droits []string
	for _, cle := range clienttype.UserRightsFor(typ) {
		if m.deps.HasAction(ids, cle) {
			droits = append(droits, cle)
		}
	}
	return Identite{User: user, Name: m.deps.Name(user), Groups: groupes, Rights: droits}, nil
}

func (m *Manager) retenir(service, user string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	comptes := m.vus[service]
	if comptes == nil {
		comptes = map[string]time.Time{}
		m.vus[service] = comptes
	}
	now := m.deps.Now()
	if len(comptes) >= maxComptesParService {
		for u, t := range comptes {
			if now.Sub(t) > m.retention {
				delete(comptes, u)
			}
		}
	}
	if len(comptes) < maxComptesParService {
		comptes[strings.ToLower(user)] = now
	}
}

func (m *Manager) aVu(service, user string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.vus[service][strings.ToLower(user)]
	return ok && m.deps.Now().Sub(t) < m.retention
}

func (m *Manager) oublier(service, user string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.vus[service], strings.ToLower(user))
}

func orTiret(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
