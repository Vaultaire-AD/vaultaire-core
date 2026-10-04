// Package ldapjournal tient le journal de l'annuaire : qui parle, ce qu'il
// demande, ce qu'on lui a répondu — TO-DO 145.
//
// # Ce que le journal LDAP était
//
// Une ligne par ÉTAPE. Une recherche en écrivait une à l'arrivée du paquet,
// une au décodage, une à la résolution, deux ou trois par entrée candidate au
// filtrage, puis une par attribut de chaque entrée rendue. Keycloak lance
// plusieurs recherches par connexion d'utilisateur : avec `debug` actif, le
// journal du core n'était plus que cela, et aucune de ces lignes ne disait à
// quelle conversation elle appartenait. Deux clients simultanés
// s'entrelaçaient sans qu'on puisse les démêler.
//
// # Ce qu'il est
//
//	ldap conn=17 ouverte LDAPS depuis 10.0.0.5:51234
//	ldap conn=17 msg=1 BIND dn="uid=svc_keycloak,ou=users,dc=acme,dc=lan" → 0 success, 38 ms
//	ldap conn=17 msg=2 SEARCH base="dc=acme,dc=lan" scope=sub filtre="(uid=alice)" attrs="uid mail" → 0 success, 1 entrée(s), 4 ms ; candidats=214
//	ldap conn=17 msg=3 UNBIND → sans réponse, 0 ms
//	ldap conn=17 fermée (unbind) après 52 ms : 3 opération(s), 1 entrée(s), compte svc_keycloak
//
// Trois règles :
//
//   - UNE ligne par opération, en DEBUG, écrite quand l'opération est finie :
//     la demande, le code de résultat, le nombre d'entrées, la durée ;
//   - TOUTE ligne de l'annuaire commence par `ldap conn=N` — et `msg=M` quand
//     elle appartient à une opération. `grep 'conn=17 '` rend une conversation
//     entière, avertissements et refus compris ;
//   - le déroulé pas à pas descend en TRACE, éteint par défaut, et porte le
//     même préfixe.
//
// `conn` est un compteur du processus : il repart de 1 au redémarrage du core
// et n'a de sens que sur CE core. `msg` est le messageID du protocole, celui
// que le client écrit dans ses propres journaux.
//
// # Pourquoi les réponses notent leur code ici
//
// La ligne d'une opération porte le code RENDU au client. Le déduire dans le
// gestionnaire aurait demandé d'en faire remonter un de chaque chemin de
// sortie — une recherche en compte une quinzaine. Ce sont donc les fonctions
// qui ÉCRIVENT sur la connexion qui le notent, là où il est connu avec
// certitude. Un test (`ecritures_test.go`) vérifie qu'aucun fichier du paquet
// LDAP n'écrit sur une connexion sans le dire à ce journal.
package ldapjournal

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

// Connexion est ce que le journal sait d'une connexion LDAP.
//
// Elle n'est lue et écrite que par la goroutine de sa connexion : une
// connexion LDAP traite ses opérations une à une, dans l'ordre. Seule la table
// qui les range est partagée.
type Connexion struct {
	ID        uint64
	Protocole string
	Adresse   string

	ouverte    time.Time
	operations int
	entrees    int
	compte     string
	courante   *Operation
}

// Operation est une opération en cours sur une connexion.
type Operation struct {
	conn      *Connexion
	messageID int
	demande   string
	debut     time.Time

	repondu  bool
	code     int
	entrees  int
	notes    []string
	terminee bool
}

var (
	// prochaine : le compteur des connexions de CE processus.
	prochaine atomic.Uint64
	// connexions range l'état par connexion. Une sync.Map : écrite à
	// l'ouverture et à la fermeture, lue à chaque ligne.
	connexions sync.Map // net.Conn → *Connexion
)

// Ouvrir enregistre une connexion et écrit sa ligne d'ouverture.
//
// `relais` est l'adresse du proxy du cluster qui a transmis la connexion, vide
// s'il n'y en a pas : l'adresse du client est alors celle qu'il a déclarée, et
// il faut pouvoir lire les deux.
//
// En INFO, comme la ligne « connection from » qu'elle remplace : c'est la
// seule trace d'une connexion qui ne se lie jamais.
func Ouvrir(conn net.Conn, protocole, relais string) *Connexion {
	c := &Connexion{
		ID:        prochaine.Add(1),
		Protocole: protocole,
		Adresse:   adresseDe(conn),
		ouverte:   time.Now(),
	}
	connexions.Store(conn, c)

	ligne := fmt.Sprintf("ldap conn=%d ouverte %s depuis %s", c.ID, protocole, c.Adresse)
	if relais != "" {
		ligne += " via le proxy " + relais
	}
	logs.Write_Log("INFO", ligne)
	return c
}

// Fermer écrit la ligne de fin d'une connexion et l'oublie.
//
// Appelée une fois, à la fermeture. Un second appel ne fait rien : l'unbind
// ferme la connexion de l'intérieur d'une opération, puis la boucle de lecture
// la referme en sortant.
func Fermer(conn net.Conn, motif string) {
	v, présente := connexions.LoadAndDelete(conn)
	if !présente {
		return
	}
	c := v.(*Connexion)
	if !logs.DebugActif(logs.SousLDAP) {
		return
	}
	qui := "aucun compte lié"
	if c.compte != "" {
		qui = "compte " + c.compte
	}
	logs.Write_Log("DEBUG", fmt.Sprintf(
		"ldap conn=%d fermée (%s) après %s : %d opération(s), %d entrée(s), %s",
		c.ID, motif, duree(time.Since(c.ouverte)), c.operations, c.entrees, qui))
}

// de rend l'état d'une connexion, nil si elle est inconnue du journal.
func de(conn net.Conn) *Connexion {
	if conn == nil {
		return nil
	}
	if v, ok := connexions.Load(conn); ok {
		return v.(*Connexion)
	}
	return nil
}

// Identifiant rend le numéro de la connexion, 0 si elle est inconnue.
func Identifiant(conn net.Conn) uint64 {
	if c := de(conn); c != nil {
		return c.ID
	}
	return 0
}

// Protocole rend « LDAP » ou « LDAPS », vide si la connexion est inconnue.
func Protocole(conn net.Conn) string {
	if c := de(conn); c != nil {
		return c.Protocole
	}
	return ""
}

// CompteLie retient le compte sous lequel la connexion s'est liée, pour la
// ligne de fermeture. Vide : la session est redevenue anonyme.
func CompteLie(conn net.Conn, compte string) {
	if c := de(conn); c != nil {
		c.compte = compte
	}
}

// Prefixe rend l'en-tête d'une ligne : « ldap conn=17 msg=3 », « ldap conn=17 »
// hors de toute opération, « ldap » pour une connexion que le journal ne
// connaît pas — refusée avant d'avoir une session, ou forgée par un test.
func Prefixe(conn net.Conn) string {
	c := de(conn)
	if c == nil {
		return "ldap "
	}
	if op := c.courante; op != nil {
		return fmt.Sprintf("ldap conn=%d msg=%d ", c.ID, op.messageID)
	}
	return fmt.Sprintf("ldap conn=%d ", c.ID)
}

// Ecrire écrit une ligne de l'annuaire, à n'importe quel niveau, précédée de
// l'identifiant de sa connexion.
//
// C'est par ici que passent les avertissements et les refus : ce sont eux
// qu'on cherche, et ce sont eux qu'il faut pouvoir rattacher à la conversation
// qui les a produits.
func Ecrire(conn net.Conn, niveau, code, message string) {
	logs.Write_LogCode(niveau, code, Prefixe(conn)+message)
}

// EcrireMeta est Ecrire avec des métadonnées — l'identifiant du compte sur un
// bind réussi.
func EcrireMeta(conn net.Conn, niveau, code, message string, meta *logs.LogMeta) {
	logs.Write_LogCodeMeta(niveau, code, Prefixe(conn)+message, meta)
}

// TraceActive dit si le déroulé pas à pas est demandé.
//
// À tester AVANT de construire un message coûteux : le filtrage d'une
// recherche passe sur chaque entrée candidate, et formater une ligne par
// entrée pour la jeter ensuite se payait sur chaque recherche du parc.
func TraceActive() bool { return logs.TraceActive(logs.SousLDAP) }

// Trace écrit une étape du déroulé. Éteint par défaut : `ldap: trace`.
func Trace(conn net.Conn, format string, args ...any) {
	if !TraceActive() {
		return
	}
	logs.Write_Log("TRACE", Prefixe(conn)+fmt.Sprintf(format, args...))
}

// Debut ouvre le journal d'une opération. `demande` est sa description, telle
// que Decrire la rend.
func Debut(conn net.Conn, messageID int, demande string) *Operation {
	c := de(conn)
	if c == nil {
		return nil
	}
	op := &Operation{conn: c, messageID: messageID, demande: demande, debut: time.Now()}
	c.courante = op
	c.operations++
	return op
}

// EnCours rend l'opération en cours sur la connexion, nil s'il n'y en a pas.
// Toutes les méthodes d'Operation acceptent nil.
func EnCours(conn net.Conn) *Operation {
	if c := de(conn); c != nil {
		return c.courante
	}
	return nil
}

// Resultat note le code rendu au client. Appelée par les fonctions qui
// écrivent une réponse sur la connexion.
//
// Le messageID est comparé : une réponse à un AUTRE message — il n'y en a pas
// aujourd'hui, le serveur répond dans l'ordre — ne doit pas s'inscrire sur
// l'opération en cours.
func Resultat(conn net.Conn, messageID, code int) {
	op := EnCours(conn)
	if op == nil || op.messageID != messageID {
		return
	}
	op.repondu = true
	op.code = code
}

// EntreeEnvoyee compte une entrée rendue au client.
func EntreeEnvoyee(conn net.Conn) {
	if op := EnCours(conn); op != nil {
		op.entrees++
	}
}

// Redire remplace la description de la demande.
//
// La boucle de lecture décrit l'opération dès qu'elle est décodée, pour que
// tout ce qui suit s'écrive sous son numéro. Mais une recherche n'est complète
// qu'une fois son contrôle de pagination rangé, ce que fait le répartiteur :
// il redit alors la demande, « page= » comprise.
func (op *Operation) Redire(demande string) {
	if op != nil {
		op.demande = demande
	}
}

// Noter ajoute un fait à la ligne de l'opération : « candidats=214 »,
// « hors-droits=3 ». Ce qui explique un résultat sans demander le déroulé.
func (op *Operation) Noter(cle string, valeur any) {
	if op == nil {
		return
	}
	op.notes = append(op.notes, fmt.Sprintf("%s=%v", cle, valeur))
}

// Trace écrit une étape du déroulé de cette opération.
func (op *Operation) Trace(format string, args ...any) {
	if op == nil || !TraceActive() {
		return
	}
	logs.Write_Log("TRACE", fmt.Sprintf("ldap conn=%d msg=%d ", op.conn.ID, op.messageID)+
		fmt.Sprintf(format, args...))
}

// Ecrire écrit une ligne de niveau quelconque au nom de cette opération.
//
// Pour le code qui reçoit l'opération sans voir la connexion — le résolveur de
// la recherche. Sans opération (nil : un test, un appel hors connexion), la
// ligne sort quand même, sous le seul préfixe « ldap » : un avertissement ne
// doit jamais se perdre faute de savoir à qui l'attribuer.
func (op *Operation) Ecrire(niveau, code, message string) {
	if op == nil {
		logs.Write_LogCode(niveau, code, "ldap "+message)
		return
	}
	logs.Write_LogCode(niveau, code,
		fmt.Sprintf("ldap conn=%d msg=%d ", op.conn.ID, op.messageID)+message)
}

// Fin écrit LA ligne de l'opération, et la détache de la connexion.
func (op *Operation) Fin() {
	if op == nil || op.terminee {
		return
	}
	op.terminee = true
	op.conn.entrees += op.entrees
	if op.conn.courante == op {
		op.conn.courante = nil
	}
	if !logs.DebugActif(logs.SousLDAP) {
		return
	}
	logs.Write_Log("DEBUG", op.ligne(time.Since(op.debut)))
}

// ligne compose la ligne d'une opération. À part, pour être éprouvée sans
// horloge.
func (op *Operation) ligne(durée time.Duration) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ldap conn=%d msg=%d %s → ", op.conn.ID, op.messageID, op.demande)
	if op.repondu {
		sb.WriteString(ldapstorage.NomDuResultat(op.code))
	} else {
		// Unbind et Abandon n'appellent aucune réponse (RFC 4511 §4.3, §4.11).
		// Pour toute autre opération, cette mention signale un défaut : le
		// client attend encore.
		sb.WriteString("sans réponse")
	}
	if op.entrees > 0 || strings.HasPrefix(op.demande, "SEARCH") {
		fmt.Fprintf(&sb, ", %d entrée(s)", op.entrees)
	}
	sb.WriteString(", " + duree(durée))
	if len(op.notes) > 0 {
		sb.WriteString(" ; " + strings.Join(op.notes, " "))
	}
	return sb.String()
}

// Decrire rend la demande d'une opération en une ligne.
//
// # Ce qui n'y figure JAMAIS
//
// Le mot de passe d'un bind, et le contenu d'une opération étendue — le
// Password Modify de la RFC 3062 y transporte l'ancien et le nouveau mot de
// passe. Le point 121 les a retirés du journal ; cette fonction ne lit ni
// `Authentication` ni `RequestValue`, sinon pour en dire la longueur ou la
// présence. `demande_test.go` le vérifie sur la ligne produite.
//
// # Ce qui vient du client est entre guillemets
//
// DN, base, attributs : `%q` neutralise les retours à la ligne. Sans cela, un
// DN forgé écrirait une fausse ligne dans le journal.
func Decrire(op ldapstorage.LDAPProtocolOperation, controles []ldapstorage.LDAPControl) string {
	var sb strings.Builder
	switch o := op.(type) {
	case ldapstorage.BindRequest:
		switch {
		case o.Name == "" && len(o.Authentication) == 0:
			sb.WriteString("BIND anonyme")
		case len(o.Authentication) == 0:
			fmt.Fprintf(&sb, "BIND dn=%q sans mot de passe", o.Name)
		default:
			fmt.Fprintf(&sb, "BIND dn=%q", o.Name)
		}
		if !o.SimpleAuth {
			sb.WriteString(" méthode=sasl")
		}
		if o.Version != 3 {
			fmt.Fprintf(&sb, " version=%d", o.Version)
		}
	case ldapstorage.SearchRequest:
		fmt.Fprintf(&sb, "SEARCH base=%q scope=%s filtre=\"%s\"",
			o.BaseObject, ldapstorage.NomDeLaPortee(o.Scope), o.Filter.Texte())
		if len(o.Attributes) > 0 {
			fmt.Fprintf(&sb, " attrs=%q", strings.Join(o.Attributes, " "))
		}
		if o.SizeLimit > 0 {
			fmt.Fprintf(&sb, " limite=%d", o.SizeLimit)
		}
		if o.Page != nil {
			fmt.Fprintf(&sb, " page=%d", o.Page.Size)
			if len(o.Page.Cookie) > 0 {
				sb.WriteString(" (suite)")
			}
		}
	case ldapstorage.ExtendedRequest:
		fmt.Fprintf(&sb, "EXTENDED oid=%q", o.RequestName)
		if n := len(o.RequestValue); n > 0 {
			fmt.Fprintf(&sb, " (%d octet(s) de contenu, non journalisé)", n)
		}
	case ldapstorage.UnbindRequest:
		sb.WriteString("UNBIND")
	default:
		if op == nil {
			sb.WriteString("opération illisible")
		} else {
			sb.WriteString(strings.ToUpper(strings.TrimSuffix(op.OpType(), "Request")))
		}
	}
	// Les contrôles AUTRES que la pagination, déjà dite par « page= » : un
	// contrôle critique inconnu fait échouer l'opération, et il faut voir
	// lequel.
	for _, c := range controles {
		if c.ControlType == ldapstorage.OIDPagedResults {
			continue
		}
		fmt.Fprintf(&sb, " contrôle=%q", c.ControlType)
		if c.Criticality {
			sb.WriteString("(critique)")
		}
	}
	return sb.String()
}

// adresseDe rend l'adresse distante, sans paniquer sur une connexion de test.
func adresseDe(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "adresse inconnue"
	}
	return conn.RemoteAddr().String()
}

// duree abrège pour la lecture : « 3 ms », « 1.2 s ». Un journal n'est pas un
// profileur, et « 3.871204ms » se lit moins vite que « 3 ms ».
func duree(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1f s", d.Seconds())
	}
	return d.Round(time.Second).String()
}
