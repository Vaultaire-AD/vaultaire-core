package keymanagement

import (
	"fmt"

	"vaultaire/core/logs"
)

// Amorçage des clés du core.
//
// # Le défaut que ce fichier ferme
//
// Les clés étaient générées par `StartDuckyServer`, appelé en GOROUTINE depuis
// main :
//
//	cluster.StartManager(db)          // lit la clé publique
//	go duckynetwork.StartDuckyServer() // la crée
//
// Sur une base neuve, le gestionnaire de cluster lisait donc une clé qui
// n'existait pas encore, et le serveur mourait sur une panique — au premier
// démarrage, celui où l'on comprend le moins ce qui se passe.
//
// Même en goroutine, l'ordre restait faux : `StartManager` est synchrone et
// s'exécute AVANT que la goroutine n'ait la moindre chance de tourner.
//
// # La règle
//
// Ce qui est un PRÉREQUIS est amorcé dans main, synchroniquement, avant tout ce
// qui pourrait le lire. Une initialisation cachée dans le démarrage d'un service
// crée un ordre implicite entre des composants qui ne se connaissent pas — et
// cet ordre-là se casse au premier réagencement, sans qu'aucun test ne le voie.

// EnsureServerKeys garantit que les clés du core existent en base.
//
// Idempotent : les deux générateurs vérifient d'abord la présence en base et ne
// font rien si elle y est. Appeler cette fonction à chaque démarrage ne coûte
// donc que deux lectures.
//
// # Pourquoi une erreur et non une panique
//
// C'est à l'appelant de décider. Sans clé, le core ne peut ni authentifier un
// client ni s'annoncer au cluster : main en fait un arrêt franc, avec un message
// qui dit quoi faire. Paniquer ici rendrait ce message impossible.
func EnsureServerKeys() error {
	if err := Generate_Serveur_Key_Pair(); err != nil {
		return fmt.Errorf("paire de clés du core : %w", err)
	}
	if err := Generate_SSH_Key_For_Login_Client(); err != nil {
		return fmt.Errorf("clé SSH de déploiement des agents : %w", err)
	}

	// L'empreinte est calculée et journalisée au démarrage.
	//
	// C'est ce qu'un administrateur recopie sur une machine du parc, et ce qu'il
	// compare quand un agent refuse la clé du core. L'avoir dans le journal de
	// démarrage évite d'aller la chercher au moment où le service ne marche pas.
	empreinte, err := EmpreinteDuCore()
	if err != nil {
		// Non fatal : les clés sont là — c'est le calcul de l'empreinte qui a
		// échoué. Le core fonctionne, il ne s'annoncera simplement pas aux
		// agents, et la ligne suivante dit pourquoi.
		logs.Write_Log("ERROR", "keymanagement: empreinte du core incalculable : "+err.Error())
		return nil
	}
	logs.Write_Log("INFO", "keymanagement: empreinte du core "+empreinte)
	return nil
}
