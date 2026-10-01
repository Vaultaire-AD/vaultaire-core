package configuration_file

import (
	"fmt"
	"strings"

	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// La configuration livrée, et le refus de démarrer dessus — TO-DO 99.
//
// # Ce que le dépôt publiait
//
// `deployments/configs/serveur_conf.yaml` portait `administreur.password:
// admin123`, `database.password: root` et `debug: true`. Le compte ainsi créé
// entre dans le groupe `vaultaire` — tous les droits, sur tous les domaines —
// et `password_changed_at` était posée au jour même : il n'était même pas
// expiré.
//
// Une installation déployée depuis les fichiers du dépôt, sans les retoucher,
// exposait donc un superadmin dont le mot de passe est publié dans le dépôt Git
// du produit. Ce n'est pas une hypothèse d'attaque : c'est la procédure
// d'installation documentée.
//
// # Pourquoi REFUSER DE DÉMARRER, et non avertir
//
// Un avertissement au démarrage est lu une fois, le jour de l'installation, par
// quelqu'un qui regarde si le service monte. Il est ensuite noyé dans le
// journal, et personne ne le relit — surtout pas six mois plus tard, quand la
// préproduction est devenue la production.
//
// Le refus, lui, arrive au seul moment où quelqu'un est devant l'écran et a le
// pouvoir de corriger. Le coût est une installation qui demande un geste de
// plus ; le bénéfice est qu'aucune installation ne peut plus porter ce mot de
// passe sans que quelqu'un l'ait DÉCIDÉ.
//
// # Ce qui n'est qu'un avertissement, et pourquoi
//
// Le mot de passe de la BASE. Il n'ouvre pas l'annuaire à qui le connaît : il
// faut d'abord joindre le port de la base, que rien n'expose par défaut. Le
// refus y serait disproportionné, et casserait les piles de développement qui
// se montent et se démontent tous les jours — donc serait contourné par une
// variable d'environnement posée une fois pour toutes, ce qui ne protège plus
// rien.

// Valeurs de démonstration publiées dans le dépôt.
//
// Écrites ici EN DUR, et c'est voulu : elles doivent être reconnues telles
// qu'elles sont dans les fichiers publiés, quelles que soient les valeurs par
// défaut du code. Le jour où une valeur du dépôt change, celle-ci reste dans la
// liste — une installation faite l'an dernier la porte encore.
var (
	motsDePasseAdminDeDemo = []string{"admin123", "password", "changeme", "CHANGEZ_MOI"}
	motsDePasseBaseDeDemo  = []string{"root", "password", "CHANGEZ_MOI"}
)

// CleAdministrateurMalOrthographiee est la clé YAML que portait le fichier
// livré, et que la structure Go n'a jamais lue.
//
// # Le défaut que cette constante rend visible
//
// Le fichier publié écrivait `administreur:` ; l'étiquette de la structure Go
// dit `administrateur:` — avec un `a` de plus. `gopkg.in/yaml.v3` apparie sur
// l'étiquette exacte, et `KnownFields` n'est pas activé sur ce décodeur : TOUTE
// la section était donc ignorée en SILENCE.
//
// Le défaut restait invisible parce que les valeurs par défaut du code étaient
// identiques à celles du fichier. Conséquence : un exploitant qui changeait le
// mot de passe dans le fichier livré démarrait quand même avec `admin123`, et
// n'avait aucun moyen de s'en apercevoir.
//
// Le fichier est corrigé, et cette détection est ce qui empêche la correction
// de casser en silence les installations qui ont recopié l'ancien : au lieu de
// repartir sur les valeurs par défaut sans rien dire, le core nomme la ligne à
// renommer.
const CleAdministrateurMalOrthographiee = "administreur:"

// SignalerCleMalOrthographiee inspecte le TEXTE du fichier de configuration.
//
// Le texte et non la structure décodée : une clé qu'aucune étiquette ne réclame
// ne laisse aucune trace après décodage, par construction. C'est précisément ce
// qui rendait le défaut indétectable.
func SignalerCleMalOrthographiee(contenu []byte) error {
	for _, ligne := range strings.Split(string(contenu), "\n") {
		if strings.HasPrefix(strings.TrimSpace(ligne), CleAdministrateurMalOrthographiee) {
			return fmt.Errorf(
				"la section « %s » n'est plus lue : elle s'écrit désormais "+
					"« administrateur: » (avec le second « a »).\n"+
					"  Cette section était ignorée en SILENCE par les versions précédentes :\n"+
					"  le compte d'amorçage naissait avec les valeurs par défaut du code,\n"+
					"  quoi que contienne le fichier. Renommez la clé, vérifiez le mot de\n"+
					"  passe qu'elle porte, puis redémarrez",
				CleAdministrateurMalOrthographiee)
		}
	}
	return nil
}

// VerifierValeursLivrees refuse de démarrer sur les valeurs du dépôt.
//
// Appelée APRÈS le chargement de la configuration et AVANT qu'aucun service
// n'écoute. Rend une erreur destinée à arrêter le démarrage ; les cas qui ne
// justifient pas un arrêt sont journalisés ici même.
func VerifierValeursLivrees() error {
	// Le mot de passe de la BASE : avertissement seulement, voir l'en-tête.
	if contient(motsDePasseBaseDeDemo, storage.Database_password) {
		logs.Write_Log("SECURITY",
			"configuration: le mot de passe de la base est une valeur de démonstration "+
				"publiée dans le dépôt. Il n'ouvre pas l'annuaire — le port de la base "+
				"n'est pas exposé par défaut — mais il ne protège rien non plus.")
	}

	// Le mode DEBUG : avertissement, parce qu'il s'active délibérément pour
	// diagnostiquer et qu'un refus rendrait le diagnostic impossible.
	//
	// Mais il est dit, et il est dit PRÉCISÉMENT : les lignes DEBUG portent les
	// DN des binds LDAP, les identifiants de groupe des décisions de permission
	// et le détail des vérifications de signature. Aucun secret, mais la
	// cartographie complète de l'annuaire et des droits, dans un fichier lisible
	// localement et sans bornage.
	if storage.Debug {
		logs.Write_Log("SECURITY",
			"configuration: le journal DEBUG est actif. Il écrit les DN des binds LDAP, "+
				"les identifiants de groupe des décisions de permission et le détail des "+
				"vérifications de signature — la cartographie de l'annuaire et des droits. "+
				"À n'activer que le temps d'un diagnostic.")
	}

	// Le mot de passe du compte d'AMORÇAGE : refus.
	if !storage.Administrateur_Enable {
		return nil
	}
	// VIDE : le défaut du code, c'est-à-dire « la configuration ne dit rien ».
	//
	// Signalé ICI plutôt qu'à l'amorçage, où le message arrivait après
	// l'ouverture de la base et le démarrage de Ducky — c'est-à-dire après que le
	// serveur a commencé à accepter des connexions.
	if strings.TrimSpace(storage.Administrateur_Password) == "" {
		return fmt.Errorf(
			"aucun mot de passe pour le compte d'amorçage.\n" +
				"  Renseignez « administrateur.password » dans le fichier de configuration,\n" +
				"  ou posez VAULTAIRE_ADMIN_PASSWORD. Si la section existe déjà, vérifiez son\n" +
				"  orthographe : « administrateur », et non « administreur ».\n" +
				"  Pour un serveur qui ne doit créer aucun compte d'amorçage, posez\n" +
				"  « administrateur.enable: false »")
	}

	if !contient(motsDePasseAdminDeDemo, storage.Administrateur_Password) {
		return nil
	}

	// Le compte existe peut-être déjà avec un autre mot de passe — l'amorçage
	// ne recrée rien. Mais on ne peut pas le savoir ici sans base, et surtout :
	// une configuration qui porte encore ce mot de passe le reposerait sur une
	// base neuve. C'est la CONFIGURATION qu'on refuse, pas l'état.
	return fmt.Errorf(
		"le mot de passe du compte d'amorçage est celui publié dans le dépôt.\n" +
			"  Ce compte entre dans le groupe « vaultaire » : tous les droits, sur tous\n" +
			"  les domaines. Le laisser tel quel revient à publier la clé de l'annuaire.\n" +
			"  Corrigez « administrateur.password » dans le fichier de configuration, ou\n" +
			"  posez VAULTAIRE_ADMIN_PASSWORD, puis redémarrez.\n" +
			"  Le mot de passe doit aussi tenir la règle de robustesse (vlt mfa policy)")
}

func contient(liste []string, valeur string) bool {
	for _, v := range liste {
		if v == valeur {
			return true
		}
	}
	return false
}

// Marqueur reconnaît une valeur que le fichier livré porte pour être remplacée.
//
// Exportée parce qu'elle sert aussi aux outils de déploiement : un marqueur
// laissé en place doit se voir avant le démarrage, pas seulement à son refus.
func Marqueur(valeur string) bool {
	return strings.HasPrefix(valeur, "CHANGEZ_MOI")
}
