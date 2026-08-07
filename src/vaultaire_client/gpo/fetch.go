package gpo

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"vaultaire_client/logs"
)

// Réception des politiques — côté client des trames 05_XX.
//
// Le client initie toujours (modèle pull) :
//
//	05_01 demande machine  → 05_02 manifeste / 05_03 rien à faire / 05_04 erreur
//	05_05 demande user     → 05_06 manifeste / 05_07 rien à faire / 05_08 erreur
//	05_09 demande fragment → 05_10 fragment  / 05_11 erreur
//	05_12 rapport          → 05_13 accusé    / 05_14 erreur
//	05_15 conformité       → 05_16 accusé    / 05_17 erreur
//
// Les réponses arrivent de façon asynchrone dans le lecteur de trames. Ce
// fichier tient donc les transferts en cours et réveille l'appelant quand la
// politique est complète ou qu'un refus est arrivé.

// Bornes d'attente d'une politique complète.
//
// Deux budgets distincts, parce que les deux moments n'ont pas les mêmes
// contraintes :
//
//   - au démarrage de la machine, personne n'attend devant un écran : on peut
//     laisser au serveur le temps de répondre ;
//   - à la connexion d'un utilisateur, l'attente s'ajoute aux deux étapes
//     d'authentification déjà écoulées et retarde d'autant l'ouverture de
//     session. Un budget serré vaut mieux qu'un utilisateur qui croit que sa
//     machine a planté.
const (
	// FetchTimeout borne l'attente en scope machine.
	FetchTimeout = 20 * time.Second
	// UserFetchTimeout borne l'attente en scope utilisateur, sur le chemin de
	// connexion. Dépasser ce délai n'empêche pas de se connecter.
	UserFetchTimeout = 6 * time.Second
)

// Outcome décrit l'issue d'une demande de politique.
type Outcome struct {
	// Policy est la politique reçue, nil si rien à appliquer ou en cas d'erreur.
	Policy *Policy
	// Unchanged indique que le serveur a répondu « rien à faire ».
	Unchanged bool
	// ErrorCode est le code de refus du serveur, vide si aucun refus.
	ErrorCode string
	// ErrorMessage accompagne ErrorCode.
	ErrorMessage string
}

// pendingFetch est une demande en cours d'aboutissement.
type pendingFetch struct {
	scope    string
	username string

	manifest struct {
		version     int
		fingerprint string
		chunkCount  int
		totalSize   int
		moduleCount int
		checksum    string
	}
	chunks   map[int][]byte
	received int

	done   chan Outcome
	closed bool
}

var (
	fetchMu     sync.Mutex
	pendingList = map[string]*pendingFetch{}
)

// fetchKey identifie une demande : scope et utilisateur cible.
func fetchKey(scope, username string) string {
	if scope == ScopeUser {
		return scope + "/" + username
	}
	return scope
}

// Sender envoie une trame vers le serveur.
//
// Injecté par le paquet réseau plutôt qu'importé : le paquet gpo serait sinon
// en dépendance croisée avec la couche d'envoi, qui a besoin de lui pour router
// les réponses.
type Sender func(trame string)

var (
	senderMu sync.RWMutex
	sender   Sender
	clientID string
)

// Configure installe l'émetteur de trames et l'identifiant machine.
func Configure(send Sender, computeurID string) {
	senderMu.Lock()
	sender = send
	clientID = computeurID
	senderMu.Unlock()
	logs.Write_log("DEBUG", "GPO: transport configure pour le client "+computeurID)
}

// send émet une trame si l'émetteur est installé.
func send(trame string) error {
	senderMu.RLock()
	s := sender
	senderMu.RUnlock()
	if s == nil {
		return fmt.Errorf("transport GPO non configure")
	}
	s(trame)
	return nil
}

// currentClientID retourne l'identifiant machine.
func currentClientID() string {
	senderMu.RLock()
	defer senderMu.RUnlock()
	return clientID
}

// startFetch enregistre une demande et retourne son canal de résultat.
//
// Une demande déjà en cours pour la même clé est abandonnée : deux cycles
// simultanés sur le même scope produiraient deux applications concurrentes des
// mêmes modules.
func startFetch(scope, username string) chan Outcome {
	fetchMu.Lock()
	defer fetchMu.Unlock()

	key := fetchKey(scope, username)
	if existing, ok := pendingList[key]; ok {
		logs.Write_log("DEBUG", "GPO: demande "+key+" deja en cours, la precedente est abandonnee")
		closeFetchLocked(existing, Outcome{ErrorCode: "superseded",
			ErrorMessage: "demande remplacee par une plus recente"})
	}

	fetch := &pendingFetch{
		scope:    scope,
		username: username,
		chunks:   map[int][]byte{},
		done:     make(chan Outcome, 1),
	}
	pendingList[key] = fetch
	return fetch.done
}

// closeFetchLocked termine une demande. Appelée sous verrou.
func closeFetchLocked(fetch *pendingFetch, outcome Outcome) {
	if fetch.closed {
		return
	}
	fetch.closed = true
	fetch.done <- outcome
	close(fetch.done)
	delete(pendingList, fetchKey(fetch.scope, fetch.username))
}

// finishFetch termine une demande depuis le lecteur de trames.
func finishFetch(scope, username string, outcome Outcome) {
	fetchMu.Lock()
	defer fetchMu.Unlock()

	key := fetchKey(scope, username)
	fetch, ok := pendingList[key]
	if !ok {
		logs.Write_log("DEBUG", "GPO: reponse recue pour "+key+" sans demande en cours, ignoree")
		return
	}
	closeFetchLocked(fetch, outcome)
}

// getFetch retourne la demande en cours pour une clé.
func getFetch(scope, username string) (*pendingFetch, bool) {
	fetchMu.Lock()
	defer fetchMu.Unlock()
	fetch, ok := pendingList[fetchKey(scope, username)]
	return fetch, ok
}

// RequestMachinePolicy demande la politique machine et attend son issue.
func RequestMachinePolicy(sessionKey string) Outcome {
	return requestPolicy(sessionKey, ScopeMachine, "", FetchTimeout)
}

// RequestUserPolicy demande la politique d'un utilisateur et attend son issue.
func RequestUserPolicy(sessionKey, username string) Outcome {
	return requestPolicy(sessionKey, ScopeUser, username, UserFetchTimeout)
}

// requestPolicy émet la demande puis attend la réponse ou le délai imparti.
func requestPolicy(sessionKey, scope, username string, timeout time.Duration) Outcome {
	applied := AppliedFingerprint(scope, username)
	done := startFetch(scope, username)

	var trame string
	if scope == ScopeUser {
		trame = buildClientTrame("05_05", sessionKey, username, applied)
		logs.Write_log("DEBUG", fmt.Sprintf(
			"GPO: 05_05 envoyee pour %s (empreinte appliquee %s)", username, ShortFingerprint(applied)))
	} else {
		trame = buildClientTrame("05_01", sessionKey, applied)
		logs.Write_log("DEBUG", fmt.Sprintf(
			"GPO: 05_01 envoyee (empreinte appliquee %s)", ShortFingerprint(applied)))
	}

	if err := send(trame); err != nil {
		finishFetch(scope, username, Outcome{ErrorCode: "transport", ErrorMessage: err.Error()})
		return Outcome{ErrorCode: "transport", ErrorMessage: err.Error()}
	}

	select {
	case outcome := <-done:
		return outcome
	case <-time.After(timeout):
		finishFetch(scope, username, Outcome{})
		logs.Write_log("WARNING", fmt.Sprintf(
			"GPO: aucune reponse du serveur en %s pour le scope %s%s", timeout, scope, userLabel(username)))
		return Outcome{ErrorCode: "timeout", ErrorMessage: "aucune reponse du serveur"}
	}
}

// buildClientTrame assemble une trame client → serveur.
func buildClientTrame(action, sessionKey string, contentLines ...string) string {
	parts := append([]string{action, "serveur_central", sessionKey, "vaultaire", currentClientID()}, contentLines...)
	return strings.Join(parts, "\n")
}

// HandleTrame traite une trame 05_XX reçue du serveur.
//
// sessionKey est nécessaire pour émettre les demandes de fragments : le
// réassemblage se poursuit en réaction aux trames, sans repasser par l'appelant.
func HandleTrame(sub, sessionKey, content string) {
	lines := splitLines(content)

	switch sub {
	case "02":
		handleManifest(sessionKey, ScopeMachine, "", lines)
	case "03":
		handleUnchanged(ScopeMachine, "", lineAt(lines, 0))
	case "04":
		handleScopeError(ScopeMachine, "", lineAt(lines, 0), lineAt(lines, 1))
	case "06":
		// En scope user, la première ligne est l'utilisateur cible : le reste du
		// manifeste suit le même format qu'en scope machine.
		username := strings.TrimSpace(lineAt(lines, 0))
		handleManifest(sessionKey, ScopeUser, username, dropFirst(lines))
	case "07":
		handleUnchanged(ScopeUser, strings.TrimSpace(lineAt(lines, 0)), lineAt(lines, 1))
	case "08":
		handleScopeError(ScopeUser, strings.TrimSpace(lineAt(lines, 0)), lineAt(lines, 1), lineAt(lines, 2))
	case "10":
		handleChunk(sessionKey, lines)
	case "11":
		handleChunkError(lines)
	case "13":
		logs.Write_log("DEBUG", "GPO: rapport d'application accuse par le serveur")
	case "14":
		logs.Write_log("WARNING", fmt.Sprintf(
			"GPO: rapport d'application refuse par le serveur (%s) : %s", lineAt(lines, 2), lineAt(lines, 3)))
	default:
		logs.Write_log("DEBUG", "GPO: sous-ordre 05_"+sub+" non gere cote client")
	}
}

// handleManifest traite 05_02 et 05_06, puis lance la récupération.
func handleManifest(sessionKey, scope, username string, lines []string) {
	fetch, ok := getFetch(scope, username)
	if !ok {
		logs.Write_log("DEBUG", "GPO: manifeste recu sans demande en cours, ignore")
		return
	}

	version, _ := strconv.Atoi(strings.TrimSpace(lineAt(lines, 0)))
	fingerprint := strings.TrimSpace(lineAt(lines, 1))
	chunkCount, err := strconv.Atoi(strings.TrimSpace(lineAt(lines, 2)))
	if err != nil || chunkCount <= 0 {
		finishFetch(scope, username, Outcome{ErrorCode: "malformed_manifest",
			ErrorMessage: "nombre de fragments illisible"})
		return
	}
	totalSize, _ := strconv.Atoi(strings.TrimSpace(lineAt(lines, 3)))
	moduleCount, _ := strconv.Atoi(strings.TrimSpace(lineAt(lines, 4)))
	checksum := strings.TrimSpace(lineAt(lines, 5))

	fetchMu.Lock()
	fetch.manifest.version = version
	fetch.manifest.fingerprint = fingerprint
	fetch.manifest.chunkCount = chunkCount
	fetch.manifest.totalSize = totalSize
	fetch.manifest.moduleCount = moduleCount
	fetch.manifest.checksum = checksum
	fetch.chunks = map[int][]byte{}
	fetch.received = 0
	fetchMu.Unlock()

	logs.Write_log("INFO", fmt.Sprintf(
		"GPO: politique %s v%d annoncee%s — %d module(s), %d fragment(s), %d octets, empreinte %s",
		scope, version, userLabel(username), moduleCount, chunkCount, totalSize, ShortFingerprint(fingerprint)))

	requestChunk(sessionKey, scope, username, fingerprint, 0)
}

// requestChunk émet une demande 05_09.
func requestChunk(sessionKey, scope, username, fingerprint string, index int) {
	trame := buildClientTrame("05_09", sessionKey, scope, username, fingerprint, strconv.Itoa(index))
	logs.Write_log("DEBUG", fmt.Sprintf("GPO: 05_09 fragment %d demande (%s%s)", index, scope, userLabel(username)))
	if err := send(trame); err != nil {
		finishFetch(scope, username, Outcome{ErrorCode: "transport", ErrorMessage: err.Error()})
	}
}

// handleChunk traite 05_10 et réassemble.
func handleChunk(sessionKey string, lines []string) {
	scope := strings.TrimSpace(lineAt(lines, 0))
	username := strings.TrimSpace(lineAt(lines, 1))
	fingerprint := strings.TrimSpace(lineAt(lines, 2))
	index, err := strconv.Atoi(strings.TrimSpace(lineAt(lines, 3)))
	if err != nil {
		logs.Write_log("WARNING", "GPO: fragment recu avec un index illisible")
		return
	}
	chunkCount, _ := strconv.Atoi(strings.TrimSpace(lineAt(lines, 4)))

	// Le fragment commence à la 6e ligne et va jusqu'au bout : il peut contenir
	// des sauts de ligne, donc on rejoint sans rien rogner.
	data := ""
	if len(lines) > 5 {
		data = strings.Join(lines[5:], "\n")
	}

	fetch, ok := getFetch(scope, username)
	if !ok {
		logs.Write_log("DEBUG", "GPO: fragment recu sans demande en cours, ignore")
		return
	}

	fetchMu.Lock()
	if fetch.manifest.fingerprint != fingerprint {
		fetchMu.Unlock()
		logs.Write_log("WARNING", "GPO: fragment recu pour une autre empreinte, ignore")
		return
	}
	if _, already := fetch.chunks[index]; !already {
		fetch.chunks[index] = []byte(data)
		fetch.received++
	}
	total := fetch.manifest.chunkCount
	if chunkCount > 0 {
		total = chunkCount
	}
	received := fetch.received
	fetchMu.Unlock()

	logs.Write_log("DEBUG", fmt.Sprintf(
		"GPO: fragment %d/%d recu (%d octets)", index+1, total, len(data)))

	if received < total {
		requestChunk(sessionKey, scope, username, fingerprint, index+1)
		return
	}
	assemble(scope, username)
}

// assemble reconstitue la politique et termine la demande.
func assemble(scope, username string) {
	fetch, ok := getFetch(scope, username)
	if !ok {
		return
	}

	fetchMu.Lock()
	var payload []byte
	complete := true
	for i := 0; i < fetch.manifest.chunkCount; i++ {
		chunk, present := fetch.chunks[i]
		if !present {
			complete = false
			break
		}
		payload = append(payload, chunk...)
	}
	manifest := fetch.manifest
	fetchMu.Unlock()

	if !complete {
		finishFetch(scope, username, Outcome{ErrorCode: "incomplete",
			ErrorMessage: "fragments manquants au reassemblage"})
		return
	}

	// La taille et la somme de contrôle valident le réassemblage. Chaque trame
	// est déjà authentifiée par AES-GCM en transit : ce qu'on vérifie ici, c'est
	// l'assemblage lui-même, pas l'intégrité réseau.
	if manifest.totalSize > 0 && len(payload) != manifest.totalSize {
		finishFetch(scope, username, Outcome{ErrorCode: "size_mismatch",
			ErrorMessage: fmt.Sprintf("%d octets reassembles au lieu de %d", len(payload), manifest.totalSize)})
		return
	}
	if manifest.checksum != "" {
		if got := Checksum(payload); got != manifest.checksum {
			finishFetch(scope, username, Outcome{ErrorCode: "checksum_mismatch",
				ErrorMessage: "somme de controle du reassemblage incorrecte"})
			return
		}
	}

	policy, err := DecodePolicy(payload)
	if err != nil {
		finishFetch(scope, username, Outcome{ErrorCode: "malformed_policy", ErrorMessage: err.Error()})
		return
	}
	if policy.Fingerprint != manifest.fingerprint {
		finishFetch(scope, username, Outcome{ErrorCode: "fingerprint_mismatch",
			ErrorMessage: "l'empreinte du document ne correspond pas au manifeste"})
		return
	}
	policy.Version = manifest.version
	if policy.Username == "" {
		policy.Username = username
	}

	logs.Write_log("DEBUG", fmt.Sprintf(
		"GPO: politique %s reassemblee (%d octets, %d module(s))", scope, len(payload), len(policy.Modules)))
	finishFetch(scope, username, Outcome{Policy: policy})
}

// handleUnchanged traite 05_03 et 05_07.
func handleUnchanged(scope, username, fingerprint string) {
	logs.Write_log("DEBUG", fmt.Sprintf(
		"GPO: politique %s%s deja a jour (empreinte %s)", scope, userLabel(username),
		ShortFingerprint(strings.TrimSpace(fingerprint))))
	finishFetch(scope, username, Outcome{Unchanged: true})
}

// handleScopeError traite 05_04 et 05_08.
func handleScopeError(scope, username, code, message string) {
	code = strings.TrimSpace(code)
	message = strings.TrimSpace(message)

	// Aucun groupe commun n'est pas un incident : c'est le cas normal d'un
	// utilisateur qui se connecte à une machine hors de ses groupes.
	if code == "no_shared_group" {
		logs.Write_log("DEBUG", fmt.Sprintf(
			"GPO: aucune GPO user pour %s sur cette machine (%s)", username, message))
	} else {
		logs.Write_log("WARNING", fmt.Sprintf(
			"GPO: le serveur refuse la politique %s%s (%s) : %s", scope, userLabel(username), code, message))
	}
	finishFetch(scope, username, Outcome{ErrorCode: code, ErrorMessage: message})
}

// handleChunkError traite 05_11.
func handleChunkError(lines []string) {
	scope := strings.TrimSpace(lineAt(lines, 0))
	username := strings.TrimSpace(lineAt(lines, 1))
	code := strings.TrimSpace(lineAt(lines, 2))
	message := strings.TrimSpace(lineAt(lines, 3))

	logs.Write_log("WARNING", fmt.Sprintf(
		"GPO: transfert %s%s interrompu (%s) : %s", scope, userLabel(username), code, message))
	finishFetch(scope, username, Outcome{ErrorCode: code, ErrorMessage: message})
}

// SendApplyReport émet la trame 05_12.
func SendApplyReport(sessionKey string, report Report) {
	lines := []string{
		report.Scope,
		report.Username,
		report.Fingerprint,
		string(report.Status),
	}
	for _, m := range report.Modules {
		lines = append(lines, strings.Join([]string{m.ModuleType, m.StateKey, string(m.Result), m.Detail}, "|"))
	}

	logs.Write_log("DEBUG", fmt.Sprintf(
		"GPO: 05_12 rapport envoye (%s%s, %s)", report.Scope, userLabel(report.Username), report.Summary()))

	if err := send(buildClientTrame("05_12", sessionKey, lines...)); err != nil {
		// Un rapport perdu est un défaut d'observabilité, pas de configuration :
		// on le journalise sans remettre en cause l'application déjà faite.
		logs.Write_log("WARNING", "GPO: rapport d'application non transmis : "+err.Error())
	}
}

// SendDriftReport émet la trame 05_15.
//
// # Pourquoi une trame distincte de 05_12
//
// 05_12 rapporte une APPLICATION : ce que l'agent vient de faire, module par
// module. 05_15 rapporte une VÉRIFICATION : ce que l'agent a constaté sans rien
// changer. Les deux se ressemblent mais ne disent pas la même chose, et les
// confondre rendrait impossible de distinguer « appliqué avec succès » de
// « toujours conforme trois semaines plus tard » — qui est justement la
// question que la détection de dérive existe pour répondre.
//
// # Ce qui voyage, et ce qui ne voyage pas
//
// Le chemin du fichier part, parce que sans lui l'administrateur ne sait pas où
// regarder. Le CONTENU ne part jamais, ni l'ancien ni le nouveau : un fichier
// géré par une GPO peut porter des clés, des jetons ou une configuration
// sensible, et un rapport de conformité n'est pas un canal d'exfiltration.
func SendDriftReport(sessionKey string, report DriftReport) error {
	lines := []string{
		report.Scope,
		report.Username,
		strconv.Itoa(report.Checked),
		strconv.Itoa(len(report.Items)),
	}
	for _, item := range report.Items {
		lines = append(lines, strings.Join([]string{
			item.StateKey,
			string(item.Kind),
			sanitizePath(item.Path),
			sanitizeDetail(item.Detail),
		}, "|"))
	}

	logs.Write_log("DEBUG", fmt.Sprintf(
		"GPO: 05_15 conformite envoyee (%s%s, %d verifie(s), %d ecart(s))",
		report.Scope, userLabel(report.Username), report.Checked, len(report.Items)))

	return send(buildClientTrame("05_15", sessionKey, lines...))
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

func splitLines(content string) []string {
	if content == "" {
		return nil
	}
	return strings.Split(content, "\n")
}

func lineAt(lines []string, index int) string {
	if index < 0 || index >= len(lines) {
		return ""
	}
	return lines[index]
}

func userLabel(username string) string {
	if username == "" {
		return ""
	}
	return "/" + username
}

// dropFirst retourne les lignes sans la première, sans paniquer sur une trame
// tronquée.
func dropFirst(lines []string) []string {
	if len(lines) <= 1 {
		return nil
	}
	return lines[1:]
}
