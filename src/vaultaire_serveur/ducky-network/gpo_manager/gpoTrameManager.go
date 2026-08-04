package gpomanager

import (
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/gpo"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Transport des GPO — catégorie de trames 05.
//
// Voir docs/Developement/Tableau_Protocole_Réseau.md, section « Détail du
// transport GPO ». Modèle pull : le client initie toujours.
//
//	05_01 demande machine  → 05_02 manifeste / 05_03 rien à faire / 05_04 erreur
//	05_05 demande user     → 05_06 manifeste / 05_07 rien à faire / 05_08 erreur
//	05_09 demande fragment → 05_10 fragment  / 05_11 erreur           (2 scopes)
//	05_12 rapport          → 05_13 accusé    / 05_14 erreur           (2 scopes)
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
	default:
		// 05_02, 03, 04, 06, 07, 08, 10, 11, 13 et 14 sont des trames
		// serveur → client : les recevoir signale un client mal implémenté.
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

// replyManifest construit 05_02 (machine) ou 05_06 (user).
//
// Le scope n'apparaît pas dans le contenu : il est porté par le numéro de trame.
// L'utilisateur cible, en revanche, est repris en scope user, parce que plusieurs
// connexions peuvent être en cours sur la même machine.
func replyManifest(sessionKey string, m gpo.Manifest) string {
	common := []string{
		strconv.Itoa(m.Version),
		m.Fingerprint,
		strconv.Itoa(m.ChunkCount),
		strconv.Itoa(m.TotalSize),
		strconv.Itoa(m.ModuleCount),
		m.Checksum,
	}
	if m.Scope == gpo.ScopeUser {
		return reply("05_06", sessionKey, append([]string{m.Username}, common...)...)
	}
	return reply("05_02", sessionKey, common...)
}

// replyUnchanged construit 05_03 (machine) ou 05_07 (user).
func replyUnchanged(sessionKey string, scope gpo.Scope, username, fingerprint string) string {
	if scope == gpo.ScopeUser {
		return reply("05_07", sessionKey, username, fingerprint)
	}
	return reply("05_03", sessionKey, fingerprint)
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
