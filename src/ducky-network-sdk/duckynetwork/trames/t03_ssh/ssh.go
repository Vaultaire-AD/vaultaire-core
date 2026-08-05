// Package ssh traite la catégorie 03 : authentification d'un utilisateur tiers.
//
// # Ce n'est pas « la catégorie de l'agent »
//
// Le nom vient de son premier usage — un agent qui autorise une connexion SSH —
// mais ce qu'elle fait est plus général : demander au core de statuer sur un
// UTILISATEUR que le programme n'est pas. Une passerelle, un portail, un proxy
// LDAP posent la même question. La catégorie a donc sa place dans le socle
// commun, au même titre que 01 et 02.
//
// # Le mot de passe ne part jamais
//
// Le core donne un sel et un aléa (03_04/03_05) ; le programme calcule un HMAC
// à partir du mot de passe et les renvoie (03_01). Le core recalcule et compare.
//
// C'est la différence avec 02_01, qui transporte le mot de passe en clair dans
// une trame chiffrée. Ici il ne quitte pas la machine du tout — ce qui compte
// quand le programme qui pose la question n'est pas celui qui devrait détenir
// le secret.
//
//	03_04  →  donne-moi le sel de cet utilisateur
//	03_05  ←  sel + aléa
//	03_01  →  voici la preuve HMAC
//	03_02  ←  autorisé : clés publiques et indicateur admin
//	03_03  ←  refusé
//
//	03_06  →  donne-moi les clés publiques de cet utilisateur
//	03_07  ←  les clés
package ssh

// Codes de la catégorie.
const (
	AskCanLogin = "03_01"
	LoginOK     = "03_02"
	LoginFailed = "03_03"
	AskSalt     = "03_04"
	SaltResp    = "03_05"
	AskUserKeys = "03_06"
	UserKeys    = "03_07"
)
