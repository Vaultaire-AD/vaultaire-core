package userauth

import (
	"fmt"
	"strings"

	"vaultaire_proxy/duckynetwork/logs"
	"vaultaire_proxy/duckynetwork/sendmessage"
	"vaultaire_proxy/duckynetwork/storage"
)

// Handler traite les trames 02 reçues.
//
// La chaîne renvoyée part au core telle quelle ; « » ne répond rien.
func (m *Manager) Handler(trames storage.Trames_struct_client, session *storage.DuckySession) string {
	switch trames.Code() {

	case Challenge:
		// Le défi est RENVOYÉ TEL QUEL, contenu entier.
		//
		// Il n'y a rien à en faire : le core ne vérifie pas que nous l'avons
		// compris, il vérifie que nous avons pu le LIRE. Or il a voyagé chiffré
		// avec la clé de session, que seul le destinataire de 01_02 possède. Le
		// renvoyer intact suffit ; en extraire un morceau le casserait.
		return sendmessage.BuildClientTrame(
			CheckAuth, "serveur_central", trames.SessionIntegritykey,
			trames.Username, session.ComputeurID, trames.Content)

	case AuthSuccess:
		return m.handleSuccess(trames, session)

	case AskInfo:
		// 02_11 : le programme lui-même est authentifié. Le core réclame son
		// inventaire avant de considérer la session établie.
		username := firstLine(trames.Content)
		if username == "" {
			username = ServiceAccount
		}
		session.Username = username
		m.resolve(Result{Username: username, Service: true})
		logs.Write("INFO", "programme authentifié auprès du core")
		return sendmessage.BuildClientTrame(
			ServeurInfo, "serveur_central", trames.SessionIntegritykey,
			username, session.ComputeurID, m.machineInfo())

	case AuthFailed:
		reason := strings.TrimSpace(trames.Content)
		logs.Write("WARNING", "authentification refusée : "+reason)
		m.resolve(Result{Err: fmt.Errorf("authentification refusée : %s", reason)})

	case CloseSession:
		logs.Write("INFO", "le core a fermé la session")
		session.IsSafe = false

	default:
		logs.Write("DEBUG", "trame 02 non traitée par le gestionnaire par défaut : "+trames.Code())
	}
	return ""
}

// handleSuccess lit un 02_04.
//
// Contenu : username, indicateur admin, puis les clés publiques du compte.
func (m *Manager) handleSuccess(trames storage.Trames_struct_client, session *storage.DuckySession) string {
	lines := strings.Split(trames.Content, "\n")
	result := Result{}
	if len(lines) > 0 {
		result.Username = strings.TrimSpace(lines[0])
	}
	if len(lines) > 1 {
		result.IsAdmin = strings.TrimSpace(lines[1]) == "true"
	}
	if len(lines) > 2 {
		// « empty » est ce que le core envoie quand le compte n'a aucune clé.
		// Le laisser passer ferait écrire la chaîne « empty » dans un
		// authorized_keys.
		if keys := strings.TrimSpace(lines[2]); keys != "" && keys != "empty" {
			result.PublicKeys = keys
		}
	}
	session.Username = result.Username
	m.resolve(result)
	logs.Write("INFO", fmt.Sprintf("%s authentifié (admin=%t)", result.Username, result.IsAdmin))

	return sendmessage.BuildClientTrame(
		ServeurInfo, "serveur_central", trames.SessionIntegritykey,
		result.Username, session.ComputeurID, m.machineInfo())
}

func (m *Manager) machineInfo() string {
	if m.MachineInfo != nil {
		return m.MachineInfo()
	}
	return DefaultMachineInfo()
}
