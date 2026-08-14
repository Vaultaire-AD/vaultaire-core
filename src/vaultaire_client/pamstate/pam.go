// Package pamstate porte l'état propre à l'agent : le canal PAM et la session
// utilisateur en cours.
//
// # Pourquoi un paquet séparé de storage
//
// `storage` est désormais celui du socle Ducky, partagé avec le proxy et les
// services. Y laisser le chemin du socket PAM et le résultat d'une
// authentification aurait fait porter à tout programme du socle des notions qui
// ne concernent que l'agent — et rendu le socle plus difficile à comprendre
// pour ceux qui n'ont pas de PAM du tout.
//
// La règle : ce qui parle du PROTOCOLE va dans le socle, ce qui parle de la
// MACHINE et de ses utilisateurs reste ici.

package pamstate

// SocketDir et SocketPath : le canal entre les modules PAM et l'agent.
//
// # Pourquoi pas /tmp
//
// Le socket portait /tmp/vaultaire_client.sock, en mode 0666. Le mot de passe
// en clair de CHAQUE connexion y transite.
//
// Deux conséquences, et la seconde donne root :
//
//   - 0666 : tout utilisateur local pouvait émettre des « check », donc tester
//     des mots de passe contre l'annuaire central, sans limite ni trace ;
//   - /tmp est accessible en écriture à tous. Quand l'agent ne tourne pas — au
//     démarrage de la machine, après un arrêt, après un plantage — n'importe
//     quel compte pouvait CRÉER le socket à cette place, recevoir les mots de
//     passe et répondre {"status":"success","is_admin":true}. Le module PAM en
//     tire directement un ajout au groupe sudo : élévation locale vers root.
//
// # Ce qui protège maintenant
//
//	/run/vaultaire/        0700, root:root  — un non-root ne peut rien y créer
//	/run/vaultaire/pam.sock 0600, root:root — seul root s'y connecte
//
// /run est un tmpfs monté par systemd, vidé au redémarrage : aucun socket
// périmé ne survit à un arrêt brutal. Le répertoire en 0700 est la protection
// principale — même si le socket disparaît, personne d'autre que root ne peut
// écrire dans le répertoire pour le remplacer.
//
// Les modules PAM tournent dans sshd, login et sudo, tous en root : restreindre
// à root ne coûte aucune fonctionnalité.
const (
	SocketDir  = "/run/vaultaire"
	SocketName = "pam.sock"
)

// SocketPath reste une variable : les tests ont besoin de la déplacer.
var SocketPath = SocketDir + "/" + SocketName

// LegacySocketPath est l'ancien emplacement.
//
// Conservé pour une seule raison : le supprimer au démarrage. Un socket laissé
// dans /tmp par une version précédente reste un point de collecte de mots de
// passe si un module PAM non mis à jour continue de s'y connecter.
const LegacySocketPath = "/tmp/vaultaire_client.sock"

type AuthResult struct {
	// Salt et Nonce ont été RETIRÉS avec le défi d'authentification.
	//
	// Ils portaient le sel du compte et le nonce du serveur jusqu'au calcul de
	// la preuve HMAC. Le mot de passe partant désormais dans le tunnel, plus
	// personne ne les remplit — et les laisser en place aurait laissé croire
	// qu'un chemin les alimente encore.
	Type    string `json:"type"` // "AUTH", "CHECK" ou "FETCH"
	IsAdmin bool   `json:"is_admin"`
	SSHKeys string `json:"ssh_keys"`

	// Accepte porte le VERDICT du serveur, explicitement.
	//
	// # Le défaut que ce champ ferme
	//
	// Il n'existait pas. Le refus (03_03) se signalait en FERMANT le canal, et
	// le lecteur côté PAM faisait `result := <-finalChan` sans le second
	// retour. Or lire un canal fermé rend le ZÉRO du type, immédiatement et
	// sans erreur : `AuthResult{}`, dont le `Type` vaut « ».
	//
	// Le test qui suivait — « si Type n'est ni vide ni AUTH, échec » — laissait
	// donc passer ce zéro dans la branche du SUCCÈS. Un mot de passe refusé par
	// le serveur central devenait un « status: success » rendu au module PAM,
	// qui ouvrait la session ET réécrivait /etc/shadow avec le mot de passe
	// essayé.
	//
	// # Pourquoi un champ et non un test plus fin
	//
	// Parce que le zéro de la structure doit vouloir dire REFUS. Tant que
	// l'acceptation se déduisait de l'absence d'information, tout chemin qui
	// oubliait de remplir la structure — canal fermé, message perdu, champ
	// ajouté ailleurs — produisait une acceptation.
	//
	// `false` par défaut : un émetteur qui oublie de le poser refuse, il
	// n'accepte pas. C'est le sens dans lequel un oubli doit se tromper.
	Accepte bool `json:"accepte"`
}
