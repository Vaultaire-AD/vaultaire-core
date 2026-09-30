package webserveur

// Le téléchargement de l'archive d'installation d'une machine — TO-DO 82.
//
// # Pourquoi un jeton, et pas simplement « /admin/clients/archive?id=… »
//
// L'archive porte une CLÉ PRIVÉE de machine. Une adresse qui la rend sur simple
// identifiant serait rejouable indéfiniment : elle finirait dans un historique
// de navigateur, dans un marque-page, dans un message. Le jeton la rend
// éphémère et à usage unique — l'équivalent, pour un fichier, de la règle déjà
// tenue par les clés d'enrôlement : on la montre une fois, jamais deux.
//
// # Ce que le jeton ne remplace PAS
//
// Il n'autorise rien par lui-même. Le téléchargement exige, en plus :
//
//   - une session d'administration valide — le jeton volé sans la session ne
//     sert à rien ;
//   - que ce soit la MÊME personne qui l'a demandé ;
//   - le droit « write:create:client », revérifié à ce moment-là par l'action.
//
// Trois contrôles pour un fichier, cela paraît beaucoup. C'est le prix d'une
// clé privée servie par HTTP : chacun d'eux ferme une porte que les deux autres
// laissent ouverte.

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"sync"
	"time"

	act "vaultaire/core/action"
	"vaultaire/core/logs"
)

// dureeJetonArchive borne la validité d'un lien de téléchargement.
//
// Cinq minutes : le temps de cliquer, pas celui d'oublier. Le lien est produit
// juste après une action de l'administrateur, qui est devant sa page — allonger
// ce délai ne servirait qu'aux cas où personne ne clique, c'est-à-dire ceux où
// le lien ne devrait plus valoir.
const dureeJetonArchive = 5 * time.Minute

type jetonArchive struct {
	computeurID string
	systeme     string
	username    string
	expire      time.Time
}

var (
	jetonsMu      sync.Mutex
	jetonsArchive = map[string]jetonArchive{}
)

// EmettreJetonArchive enregistre un droit de téléchargement à usage unique.
//
// En mémoire et non en base : un jeton de cinq minutes qui survivrait au
// redémarrage du core n'aurait aucun sens, et une table de plus pour des lignes
// qui vivent moins qu'un cycle de GPO serait une table à purger.
func EmettreJetonArchive(username, computeurID, systeme string) (string, error) {
	brut := make([]byte, 16)
	if _, err := rand.Read(brut); err != nil {
		return "", err
	}
	jeton := hex.EncodeToString(brut)

	jetonsMu.Lock()
	defer jetonsMu.Unlock()
	purgerJetonsExpires()
	jetonsArchive[jeton] = jetonArchive{
		computeurID: computeurID,
		systeme:     systeme,
		username:    username,
		expire:      time.Now().Add(dureeJetonArchive),
	}
	return jeton, nil
}

// purgerJetonsExpires retire les jetons périmés. Appelée sous verrou.
//
// À l'émission plutôt que par une boucle : la carte ne grandit qu'à ce
// moment-là, et une goroutine de ménage pour quelques entrées de cinq minutes
// serait un fil de plus à comprendre pour rien.
func purgerJetonsExpires() {
	maintenant := time.Now()
	for j, v := range jetonsArchive {
		if maintenant.After(v.expire) {
			delete(jetonsArchive, j)
		}
	}
}

// consommerJetonArchive rend le jeton et le retire, qu'il soit valide ou non.
//
// Retiré même expiré : un jeton présenté une fois ne doit plus jamais servir,
// et le garder pour distinguer « expiré » de « inconnu » donnerait un oracle
// sans rien apporter à qui l'utilise correctement.
func consommerJetonArchive(jeton string) (jetonArchive, bool) {
	jetonsMu.Lock()
	defer jetonsMu.Unlock()
	v, ok := jetonsArchive[jeton]
	if !ok {
		return jetonArchive{}, false
	}
	delete(jetonsArchive, jeton)
	if time.Now().After(v.expire) {
		return jetonArchive{}, false
	}
	return v, true
}

// AdminClientArchiveHandler sert l'archive d'installation d'une machine.
func AdminClientArchiveHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}

	v, ok := consommerJetonArchive(r.URL.Query().Get("jeton"))
	if !ok {
		// Un seul message pour « inconnu », « expiré » et « déjà servi ». Les
		// distinguer dirait à qui essaie des jetons au hasard lesquels ont
		// existé.
		logs.Write_LogCode("WARNING", logs.CodeWebAdmin,
			"webadmin: téléchargement d'archive refusé pour "+username+" : jeton invalide ou déjà utilisé")
		http.Error(w, "Lien de téléchargement invalide ou expiré. Relancez l'export depuis la page Clients.",
			http.StatusForbidden)
		return
	}
	if v.username != username {
		// Le jeton a été émis pour quelqu'un d'autre. Il est déjà consommé, donc
		// perdu pour son destinataire légitime : c'est voulu, un jeton qui a
		// circulé ne doit plus servir.
		logs.Write_LogCode("SECURITY", logs.CodeWebAdmin,
			"webadmin: "+username+" a présenté un jeton d'archive émis pour "+v.username+
				" — machine "+v.computeurID)
		http.Error(w, "Lien de téléchargement invalide ou expiré.", http.StatusForbidden)
		return
	}

	// L'action refait le contrôle de droit et recompose l'archive. Recomposer
	// plutôt que garder les octets en mémoire : un droit retiré entre la demande
	// et le clic doit refuser, et la liste des cores doit être celle de
	// maintenant.
	res, err := act.Executer("client.export",
		act.Appelant{Username: username, GroupIDs: groupIDs},
		act.Params{"computeur_id": v.computeurID, "systeme": v.systeme})
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeWebAdmin,
			"webadmin: archive de "+v.computeurID+" refusée à "+username+" : "+err.Error())
		http.Error(w, MessageDActionPourAffichage(res, err), http.StatusForbidden)
		return
	}

	archive, ok := res.Donnees.(act.ArchiveClient)
	if !ok {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: archive illisible dans le résultat")
		http.Error(w, "Erreur interne du serveur", http.StatusInternalServerError)
		return
	}

	// Qui a téléchargé l'identité de quelle machine, et quand. C'est la seule
	// trace qui existera le jour où l'on cherche par où une clé privée est
	// sortie.
	logs.Write_Log("SECURITY", "webadmin: "+username+" a telecharge l'identite de "+
		archive.ComputeurID+" ("+archive.Systeme+")")

	// no-store, et pas seulement no-cache : « no-cache » autorise la mise en
	// cache à condition de revalider. Pour une clé privée, ce n'est pas la
	// fraîcheur qui compte, c'est qu'il n'en reste aucune copie.
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+archive.NomFichier+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(archive.Contenu)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := w.Write(archive.Contenu); err != nil {
		logs.Write_Log("WARNING", "webadmin: envoi de l'archive interrompu : "+err.Error())
	}
}
