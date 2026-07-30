package gpomanager

import (
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/database"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Handlers des trames entrantes de la catégorie 05.

// handleAskMachine traite 05_01 et répond 05_02, 05_03 ou 05_04.
func handleAskMachine(trames storage.Trames_struct_client) string {
	clientID := trames.ClientSoftwareID
	appliedFingerprint := normalizeFingerprint(lineAt(contentLines(trames.Content), 0))

	logs.Write_LogCode("DEBUG", logs.CodeGPOTransport, fmt.Sprintf(
		"gpo: 05_01 du client %s, empreinte appliquée %s", clientID, shortFingerprint(appliedFingerprint)))

	db := database.GetDatabase()
	if db == nil {
		logs.Write_LogCode("ERROR", logs.CodeGPOResolve, "gpo: base indisponible pour la résolution machine")
		return replyScopeError(trames.SessionIntegritykey, gpo.ScopeMachine, "", errInternal, "base indisponible")
	}

	// Les restrictions sont fail-closed : sans elles, la politique résolue serait
	// vide et le client effacerait sa configuration. On refuse explicitement.
	if !gpo.RestrictionsAreLoaded() {
		reason := gpo.LastRestrictionError()
		logs.Write_LogCode("ERROR", logs.CodeGPORestrictions, fmt.Sprintf(
			"gpo: restrictions non chargées, refus de livrer une politique machine à %s — %s", clientID, reason))
		return replyScopeError(trames.SessionIntegritykey, gpo.ScopeMachine, "",
			errRestrictionsUnavailable, reason)
	}

	policy, err := resolveMachinePolicy(db, clientID)
	if err != nil {
		code, message := classifyResolveError(err)
		logs.Write_LogCode("WARNING", logs.CodeGPOResolve, fmt.Sprintf(
			"gpo: résolution machine échouée pour %s (%s) : %s", clientID, code, message))
		return replyScopeError(trames.SessionIntegritykey, gpo.ScopeMachine, "", code, message)
	}

	return serveScope(trames, gpo.ScopeMachine, "", policy, appliedFingerprint)
}

// handleAskUser traite 05_05 et répond 05_06, 05_07 ou 05_08.
func handleAskUser(trames storage.Trames_struct_client) string {
	clientID := trames.ClientSoftwareID
	lines := contentLines(trames.Content)
	targetUser := strings.TrimSpace(lineAt(lines, 0))
	appliedFingerprint := normalizeFingerprint(lineAt(lines, 1))

	logs.Write_LogCode("DEBUG", logs.CodeGPOTransport, fmt.Sprintf(
		"gpo: 05_05 du client %s pour l'utilisateur %q, empreinte appliquée %s",
		clientID, targetUser, shortFingerprint(appliedFingerprint)))

	if targetUser == "" {
		logs.Write_LogCode("WARNING", logs.CodeGPOTransport,
			"gpo: 05_05 sans utilisateur cible reçue du client "+clientID)
		return replyScopeError(trames.SessionIntegritykey, gpo.ScopeUser, "",
			errMalformedRequest, "utilisateur cible manquant")
	}

	db := database.GetDatabase()
	if db == nil {
		logs.Write_LogCode("ERROR", logs.CodeGPOResolve, "gpo: base indisponible pour la résolution user")
		return replyScopeError(trames.SessionIntegritykey, gpo.ScopeUser, targetUser, errInternal, "base indisponible")
	}

	if !gpo.RestrictionsAreLoaded() {
		reason := gpo.LastRestrictionError()
		logs.Write_LogCode("ERROR", logs.CodeGPORestrictions, fmt.Sprintf(
			"gpo: restrictions non chargées, refus de livrer une politique user à %s/%s — %s",
			clientID, targetUser, reason))
		return replyScopeError(trames.SessionIntegritykey, gpo.ScopeUser, targetUser,
			errRestrictionsUnavailable, reason)
	}

	if _, err := database.Get_User_ID_By_Username(db, targetUser); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeGPOResolve, fmt.Sprintf(
			"gpo: utilisateur %s inconnu, demandé par le client %s", targetUser, clientID))
		return replyScopeError(trames.SessionIntegritykey, gpo.ScopeUser, targetUser,
			errUnknownUser, "utilisateur inconnu de l'annuaire")
	}

	// Aucun groupe commun n'est pas une erreur de configuration : c'est le cas
	// normal d'un utilisateur qui se connecte à une machine hors de ses groupes.
	// On le distingue quand même d'une politique vide, pour que le client puisse
	// le journaliser correctement plutôt que de croire à une GPO sans module.
	if !HasSharedGroup(db, targetUser, clientID) {
		logs.Write_LogCode("DEBUG", logs.CodeGPOResolve, fmt.Sprintf(
			"gpo: aucun groupe commun entre %s et %s", targetUser, clientID))
		return replyScopeError(trames.SessionIntegritykey, gpo.ScopeUser, targetUser,
			errNoSharedGroup, "aucun groupe commun entre l'utilisateur et la machine")
	}

	policy, err := resolveUserPolicy(db, targetUser, clientID)
	if err != nil {
		code, message := classifyResolveError(err)
		logs.Write_LogCode("WARNING", logs.CodeGPOResolve, fmt.Sprintf(
			"gpo: résolution user échouée pour %s sur %s (%s) : %s", targetUser, clientID, code, message))
		return replyScopeError(trames.SessionIntegritykey, gpo.ScopeUser, targetUser, code, message)
	}

	return serveScope(trames, gpo.ScopeUser, targetUser, policy, appliedFingerprint)
}

// serveScope compare l'empreinte annoncée par le client à celle de la politique
// résolue, et répond soit « rien à faire », soit un manifeste.
func serveScope(trames storage.Trames_struct_client, scope gpo.Scope, targetUser string,
	policy gpo.Policy, appliedFingerprint string) string {

	clientID := trames.ClientSoftwareID

	transfer, err := gpo.PrepareTransfer(policy, targetUser)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeGPOTransport, fmt.Sprintf(
			"gpo: préparation du transfert %s échouée pour %s : %v", scope, clientID, err))
		return replyScopeError(trames.SessionIntegritykey, scope, targetUser, errInternal, err.Error())
	}
	manifest := transfer.Manifest

	if appliedFingerprint == manifest.Fingerprint {
		logs.Write_LogCode("DEBUG", logs.CodeGPOTransport, fmt.Sprintf(
			"gpo: politique %s à jour pour %s%s (empreinte %s), rien à envoyer",
			scope, clientID, userSuffix(targetUser), shortFingerprint(manifest.Fingerprint)))
		// Un transfert éventuellement en cours pour ce scope n'a plus lieu d'être.
		dropTransfer(transferKey{ClientID: clientID, Scope: scope, Username: targetUser})
		return replyUnchanged(trames.SessionIntegritykey, scope, targetUser, manifest.Fingerprint)
	}

	storeTransfer(transferKey{ClientID: clientID, Scope: scope, Username: targetUser}, transfer)

	logs.Write_Log("INFO", fmt.Sprintf(
		"gpo: politique %s v%d proposée à %s%s — %d module(s), %d fragment(s), empreinte %s (le client appliquait %s)",
		scope, manifest.Version, clientID, userSuffix(targetUser), manifest.ModuleCount,
		manifest.ChunkCount, shortFingerprint(manifest.Fingerprint), shortFingerprint(appliedFingerprint)))

	return replyManifest(trames.SessionIntegritykey, manifest)
}

// handleAskChunk traite 05_09 et répond 05_10 ou 05_11.
func handleAskChunk(trames storage.Trames_struct_client) string {
	lines := contentLines(trames.Content)
	scope := gpo.Scope(strings.TrimSpace(lineAt(lines, 0)))
	targetUser := strings.TrimSpace(lineAt(lines, 1))
	fingerprint := strings.TrimSpace(lineAt(lines, 2))
	indexRaw := strings.TrimSpace(lineAt(lines, 3))
	clientID := trames.ClientSoftwareID

	if !gpo.IsValidPolicyScope(scope) {
		logs.Write_LogCode("WARNING", logs.CodeGPOTransfer, fmt.Sprintf(
			"gpo: 05_09 avec un scope invalide %q du client %s", scope, clientID))
		return replyChunkError(trames.SessionIntegritykey, scope, targetUser,
			errMalformedRequest, "scope invalide")
	}
	index, err := strconv.Atoi(indexRaw)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeGPOTransfer, fmt.Sprintf(
			"gpo: 05_09 avec un index illisible %q du client %s", indexRaw, clientID))
		return replyChunkError(trames.SessionIntegritykey, scope, targetUser,
			errBadIndex, "index de fragment illisible")
	}

	key := transferKey{ClientID: clientID, Scope: scope, Username: targetUser}
	transfer, failure := getTransfer(key, fingerprint)
	if failure != "" {
		message := "transfert inconnu ou expiré ; recommencez par une demande 05_01 ou 05_05"
		if failure == errStaleFingerprint {
			message = "la politique a changé depuis le manifeste ; recommencez par une demande 05_01 ou 05_05"
		}
		logs.Write_LogCode("WARNING", logs.CodeGPOTransfer, fmt.Sprintf(
			"gpo: fragment %d refusé pour %s (%s), empreinte demandée %s",
			index, key, failure, shortFingerprint(fingerprint)))
		return replyChunkError(trames.SessionIntegritykey, scope, targetUser, failure, message)
	}

	chunk, err := transfer.Chunk(index)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeGPOTransfer, fmt.Sprintf(
			"gpo: fragment %d hors bornes pour %s : %v", index, key, err))
		return replyChunkError(trames.SessionIntegritykey, scope, targetUser, errBadIndex, err.Error())
	}

	logs.Write_LogCode("DEBUG", logs.CodeGPOTransfer, fmt.Sprintf(
		"gpo: fragment %d/%d envoyé pour %s (%d octets)",
		index+1, transfer.Manifest.ChunkCount, key, len(chunk)))

	// Le dernier fragment livré libère le transfert : le garder n'apporterait rien
	// et retiendrait la charge en mémoire jusqu'à expiration.
	if index == transfer.Manifest.ChunkCount-1 {
		dropTransfer(key)
	}

	return reply("05_10", trames.SessionIntegritykey,
		string(scope), targetUser, fingerprint,
		strconv.Itoa(index), strconv.Itoa(transfer.Manifest.ChunkCount),
		string(chunk))
}

// handleApplyReport traite 05_12 et répond 05_13 ou 05_14.
//
// Le rapport est la seule source d'information du serveur sur ce qui a
// réellement été appliqué : sans lui, l'interface présenterait la configuration
// voulue comme si c'était la configuration réelle.
func handleApplyReport(trames storage.Trames_struct_client) string {
	lines := contentLines(trames.Content)
	scope := gpo.Scope(strings.TrimSpace(lineAt(lines, 0)))
	targetUser := strings.TrimSpace(lineAt(lines, 1))
	fingerprint := strings.TrimSpace(lineAt(lines, 2))
	status := strings.TrimSpace(lineAt(lines, 3))
	clientID := trames.ClientSoftwareID

	if !gpo.IsValidPolicyScope(scope) || fingerprint == "" || !gpo.IsValidApplyStatus(status) {
		logs.Write_LogCode("WARNING", logs.CodeGPOApplyReport, fmt.Sprintf(
			"gpo: rapport malformé du client %s (scope=%q empreinte=%q statut=%q)",
			clientID, scope, shortFingerprint(fingerprint), status))
		return replyReportError(trames.SessionIntegritykey, scope, targetUser,
			errMalformedReport, "scope, empreinte ou statut invalide")
	}

	report := gpo.ApplyReport{
		Scope:       scope,
		Username:    targetUser,
		Fingerprint: fingerprint,
		Status:      gpo.ApplyStatus(status),
	}

	for i := 4; i < len(lines); i++ {
		raw := strings.TrimSpace(lines[i])
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "|", 4)
		if len(parts) < 3 {
			logs.Write_LogCode("WARNING", logs.CodeGPOApplyReport, fmt.Sprintf(
				"gpo: ligne de rapport ignorée (format attendu type|clé|résultat|détail) : %q", raw))
			continue
		}
		result := parts[2]
		if !gpo.IsValidApplyResult(result) {
			logs.Write_LogCode("WARNING", logs.CodeGPOApplyReport, fmt.Sprintf(
				"gpo: résultat de module inconnu %q dans le rapport de %s", result, clientID))
			continue
		}
		detail := ""
		if len(parts) == 4 {
			detail = parts[3]
		}
		report.Modules = append(report.Modules, gpo.ModuleReport{
			ModuleType: parts[0],
			StateKey:   parts[1],
			Result:     gpo.ApplyResult(result),
			Detail:     detail,
		})
	}

	logApplyReport(clientID, report)

	return reply("05_13", trames.SessionIntegritykey, string(scope), targetUser, fingerprint)
}

// logApplyReport journalise un rapport d'application au bon niveau.
//
// Le niveau dépend du résultat : un échec d'application sur un parc doit
// remonter au même titre qu'un incident de sécurité, parce que la machine
// concernée n'est plus dans l'état que l'administrateur croit.
func logApplyReport(clientID string, report gpo.ApplyReport) {
	target := clientID + userSuffix(report.Username)
	base := fmt.Sprintf("gpo: rapport %s de %s — empreinte %s, %s",
		report.Scope, target, shortFingerprint(report.Fingerprint), report.Summary())

	switch report.Status {
	case gpo.ApplyStatusApplied:
		logs.Write_Log("INFO", base)
	case gpo.ApplyStatusPartial:
		logs.Write_Log("WARNING", base)
	default:
		logs.Write_Log("ERROR", base)
	}

	for _, m := range report.FailedModules() {
		logs.Write_LogCode("ERROR", logs.CodeGPOApplyReport, fmt.Sprintf(
			"gpo: module %s (%s) en échec sur %s — %s", m.ModuleType, m.StateKey, target, m.Detail))
	}
	for _, m := range report.Modules {
		logs.Write_LogCode("DEBUG", logs.CodeGPOApplyReport, fmt.Sprintf(
			"gpo: %s · %s · %s · %s", target, m.StateKey, m.Result, m.Detail))
	}
}

// userSuffix formate l'utilisateur cible pour les messages de journal.
func userSuffix(username string) string {
	if username == "" {
		return ""
	}
	return "/" + username
}
