package gpomanager

import (
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/gpo"
	"vaultaire/core/logs"
	"vaultaire/core/reglages"
	"vaultaire/core/storage"
)

// Transport des GPO — catégorie de trames 05.
//
// Voir docs/Developement/how it work/Protocole_Ducky.md, section « Détail du
// transport GPO ». Modèle pull : le client initie toujours.
//
//	05_01 demande machine  → 05_02 manifeste / 05_03 rien à faire / 05_04 erreur
//	05_05 demande user     → 05_06 manifeste / 05_07 rien à faire / 05_08 erreur
//	05_09 demande fragment → 05_10 fragment  / 05_11 erreur           (2 scopes)
//	05_12 rapport          → 05_13 accusé    / 05_14 erreur           (2 scopes)
//	05_15 conformité       → 05_16 accusé    / 05_17 erreur           (2 scopes)
//
//	05_18 « rafraîchis maintenant » — la SEULE trame 05 émise par le serveur de
//	      lui-même, et elle ne transporte aucune politique : elle fait repartir
//	      le client sur une 05_01 ordinaire (voir rafraichissement.go).
//
// Chaque demande est suivie de ses réponses : le numéro de trame porte le scope
// pour tout ce qui est spécifique à un scope, le scope ne voyage dans le contenu
// que pour les deux blocs partagés (fragment et rapport).

// Codes d'erreur des trames 05_04, 05_08, 05_11 et 05_14.
const (
	errNoGroups                = "no_groups"
	errResolveConflict         = "resolve_conflict"
	errRestrictionsUnavailable = "restrictions_unavailable"
	errUnknownClient           = "unknown_client"
	errUnknownUser             = "unknown_user"
	errNoSharedGroup           = "no_shared_group"
	errStaleFingerprint        = "stale_fingerprint"
	errBadIndex                = "bad_index"
	errUnknownTransfer         = "unknown_transfer"
	errMalformedReport         = "malformed_report"
	errUnknownFingerprint      = "unknown_fingerprint"
	errInternal                = "internal"
	errMalformedRequest        = "malformed_request"
	errStorage                 = "storage"
)

// fingerprintNone est la valeur envoyée par un client qui n'a encore rien appliqué.
const fingerprintNone = "none"

// GPO_Trame_Manager route les trames de la catégorie 05.
func GPO_Trame_Manager(trames storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	if len(trames.Message_Order) < 2 {
		logs.Write_LogCode("WARNING", logs.CodeGPOTransport, "gpo: trame 05 sans sous-ordre")
		return ""
	}
	sub := trames.Message_Order[1]

	logs.Write_LogCode("DEBUG", logs.CodeGPOTransport, fmt.Sprintf(
		"gpo: trame 05_%s reçue du client %s (%d octets de contenu)",
		sub, trames.ClientSoftwareID, len(trames.Content)))

	switch sub {
	case "01":
		return handleAskMachine(trames)
	case "05":
		return handleAskUser(trames)
	case "09":
		return handleAskChunk(trames)
	case "12":
		return handleApplyReport(trames)
	case "15":
		return handleDriftReport(trames)
	default:
		// 05_02, 03, 04, 06, 07, 08, 10, 11, 13, 14, 16, 17 et 18 sont des
		// trames serveur → client : les recevoir signale un client mal
		// implémenté.
		logs.Write_LogCode("WARNING", logs.CodeGPOTransport, fmt.Sprintf(
			"gpo: sous-ordre 05_%s inattendu en réception serveur (client %s)", sub, trames.ClientSoftwareID))
		return ""
	}
}

// ---------------------------------------------------------------------------
// Construction des réponses
// ---------------------------------------------------------------------------

// reply assemble une trame serveur → client : action, destination, clé de
// session, puis les lignes de contenu.
func reply(action, sessionKey string, contentLines ...string) string {
	parts := append([]string{action, "serveur_central", sessionKey}, contentLines...)
	return strings.Join(parts, "\n")
}

// PrefixeCadence ouvre la ligne de cadence des réponses machine (05_02, 05_03).
//
// # Pourquoi la cadence voyage avec la politique
//
// `gpo_refresh_minutes` est un réglage du core, mais la boucle qu'il pilote
// tourne sur l'AGENT — exactement le cas de `group_sync_minutes` et de la trame
// 03_09, dont ceci reprend la recette.
//
// Une constante côté agent aurait laissé deux valeurs à tenir d'accord, dont
// une invisible depuis l'interface : un réglage qui s'affiche sans rien changer
// au comportement est plus trompeur que pas de réglage du tout.
//
// La ligne est AJOUTÉE EN QUEUE et reconnue à son PRÉFIXE, jamais à son rang.
// Un agent resté à l'ancienne version lit les champs qu'il connaît et ignore
// celui-ci ; un core ancien ne l'envoie pas, et l'agent garde son défaut. Même
// arbitrage que le port et l'empreinte dans 04_01.
const PrefixeCadence = "refresh:"

// ligneCadence rend « refresh:<minutes> », ou une chaîne vide si la cadence est
// aberrante — auquel cas l'agent garde la sienne, ce qui vaut mieux que de lui
// faire appliquer un zéro.
func ligneCadence() string {
	minutes := reglages.Valeur(reglages.CleRafraichissementGPO)
	if minutes <= 0 {
		return ""
	}
	return PrefixeCadence + strconv.Itoa(minutes)
}

// avecCadence ajoute la ligne de cadence aux lignes d'une réponse MACHINE.
//
// Les réponses de scope USER n'en portent pas : un cycle utilisateur est
// déclenché par une ouverture de session, pas par une boucle — il n'y a aucune
// cadence à régler de ce côté.
func avecCadence(lignes []string) []string {
	if c := ligneCadence(); c != "" {
		return append(lignes, c)
	}
	return lignes
}

// replyManifest construit 05_02 (machine) ou 05_06 (user).
//
// Le scope n'apparaît pas dans le contenu : il est porté par le numéro de trame.
// L'utilisateur cible, en revanche, est repris en scope user, parce que plusieurs
// connexions peuvent être en cours sur la même machine.
//
// # Les lignes de queue
//
// La cadence (`refresh:`) ne part qu'en scope machine — un cycle utilisateur
// n'a pas de boucle à régler. La signature (`sig:`) et l'exigence (`sigreq:`),
// elles, partent dans les DEUX scopes : une politique utilisateur se signe
// comme une autre, et c'est même celle dont le contenu atterrit dans un `HOME`.
func replyManifest(sessionKey, clientID string, m gpo.Manifest) string {
	common := []string{
		strconv.Itoa(m.Version),
		m.Fingerprint,
		strconv.Itoa(m.ChunkCount),
		strconv.Itoa(m.TotalSize),
		strconv.Itoa(m.ModuleCount),
		m.Checksum,
	}
	if m.Scope == gpo.ScopeUser {
		lignes := append([]string{m.Username}, common...)
		return reply("05_06", sessionKey, append(lignes, lignesSignature(clientID, m)...)...)
	}
	return reply("05_02", sessionKey,
		append(avecCadence(common), lignesSignature(clientID, m)...)...)
}

// replyUnchanged construit 05_03 (machine) ou 05_07 (user).
func replyUnchanged(sessionKey string, scope gpo.Scope, username, fingerprint string) string {
	if scope == gpo.ScopeUser {
		return reply("05_07", sessionKey, username, fingerprint)
	}
	// 05_03 dit « rien à faire » — et c'est justement le cas le plus fréquent,
	// donc le seul chemin par lequel une cadence modifiée atteindra un parc
	// dont la politique ne bouge pas.
	return reply("05_03", sessionKey, avecCadence([]string{fingerprint})...)
}

// replyScopeError construit 05_04 (machine) ou 05_08 (user).
func replyScopeError(sessionKey string, scope gpo.Scope, username, code, message string) string {
	if scope == gpo.ScopeUser {
		return reply("05_08", sessionKey, username, code, message)
	}
	return reply("05_04", sessionKey, code, message)
}

// replyChunkError construit 05_11.
func replyChunkError(sessionKey string, scope gpo.Scope, username, code, message string) string {
	return reply("05_11", sessionKey, string(scope), username, code, message)
}

// replyDriftError construit 05_17.
func replyDriftError(sessionKey string, scope gpo.Scope, username, code, message string) string {
	return reply("05_17", sessionKey, string(scope), username, code, message)
}

// replyReportError construit 05_14.
func replyReportError(sessionKey string, scope gpo.Scope, username, code, message string) string {
	return reply("05_14", sessionKey, string(scope), username, code, message)
}

// ---------------------------------------------------------------------------
// Utilitaires de lecture de contenu
// ---------------------------------------------------------------------------

// contentLines découpe le contenu d'une trame en lignes.
//
// Aucun TrimSpace global : le contenu d'un fragment peut légitimement commencer
// ou finir par un blanc, et le rogner corromprait le réassemblage.
func contentLines(content string) []string {
	if content == "" {
		return nil
	}
	return strings.Split(content, "\n")
}

// lineAt retourne la ligne d'index donné, ou "" si absente.
func lineAt(lines []string, index int) string {
	if index < 0 || index >= len(lines) {
		return ""
	}
	return lines[index]
}

// normalizeFingerprint ramène une empreinte absente à la valeur conventionnelle.
func normalizeFingerprint(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fingerprintNone
	}
	return value
}

// classifyResolveError traduit une erreur de résolution en code de protocole.
//
// Le client ne peut rien faire d'un message libre ; le code lui dit s'il doit
// réessayer plus tard, considérer qu'il n'a rien à appliquer, ou alerter.
func classifyResolveError(err error) (string, string) {
	if err == nil {
		return "", ""
	}
	message := err.Error()
	lower := strings.ToLower(message)

	switch {
	case strings.Contains(lower, "résolution impossible"):
		return errResolveConflict, message
	case strings.Contains(lower, "introuvable") && strings.Contains(lower, "client"):
		return errUnknownClient, message
	case strings.Contains(lower, "restrictions"):
		return errRestrictionsUnavailable, message
	default:
		return errInternal, message
	}
}
