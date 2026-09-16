package action

import (
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/database"
	dbusers "vaultaire/core/database/db_users"
)

// Clés publiques SSH des utilisateurs.
//
// # Pourquoi ces actions comptent plus que leur taille ne le suggère
//
// Une clé publique ajoutée à un compte permet de s'y connecter SANS mot de
// passe, sur toutes les machines du parc où ce compte est provisionné. Ajouter
// une clé à un compte tiers revient donc à s'en donner l'accès permanent — et
// l'opération ne laisse aucune trace visible pour son titulaire, qui n'a pas de
// raison d'aller inspecter la liste de ses clés.
//
// C'est pourquoi la portée est celle du compte visé, et la clé RBAC celle qui
// modifie un utilisateur.

// EnregistrerActionsClesUtilisateur ajoute les actions de clés au registre.
func EnregistrerActionsClesUtilisateur(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "user.add_key",
		CleRBAC:  "write:update:user",
		Portee:   PorteeUtilisateur,
		Resume:   "ajoute une clé publique SSH à un compte",
		Executer: ajouterCleUtilisateur,
	})

	r.MustEnregistrer(Definition{
		Nom:      "user.remove_key",
		CleRBAC:  "write:update:user",
		Portee:   PorteeUtilisateur,
		Resume:   "retire une clé publique SSH d'un compte",
		Executer: retirerCleUtilisateur,
	})
}

// typesDeClesAcceptes limite les algorithmes admis.
//
// La version en ligne de commande n'acceptait que ssh-rsa et ssh-ed25519. La
// liste est reprise et complétée par les types ECDSA, refusés jusqu'ici sans
// raison apparente — une clé ECDSA est parfaitement utilisable par OpenSSH, et
// son refus obligeait à en générer une autre sans que le message l'explique.
//
// Ce qui reste exclu l'est délibérément : ssh-dss (DSA) est désactivé par
// défaut dans OpenSSH depuis la version 7.0, et une clé de ce type serait
// acceptée ici pour être ensuite ignorée par le serveur SSH — un échec de
// connexion sans cause visible.
var typesDeClesAcceptes = []string{
	"ssh-rsa",
	"ssh-ed25519",
	"ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp384",
	"ecdsa-sha2-nistp521",
	"sk-ssh-ed25519@openssh.com",
	"sk-ecdsa-sha2-nistp256@openssh.com",
}

func ajouterCleUtilisateur(_ Appelant, p Params) (Resultat, error) {
	cible := p.Get("username")
	label := p.Get("label")
	cle := strings.TrimSpace(p.Brut("key"))

	if cible == "" {
		return Resultat{}, fmt.Errorf("utilisateur cible requis")
	}
	if label == "" {
		return Resultat{}, fmt.Errorf("libellé requis : il identifie la clé pour la retirer plus tard")
	}
	// Une clé sur plusieurs lignes casserait authorized_keys : chaque ligne y
	// est une clé distincte, et la seconde moitié deviendrait une entrée
	// invalide — ou pire, une entrée valide qu'on n'a pas voulu ajouter.
	// Le détail des contrôles est dans ValiderCleSSH, partagée avec /profil.
	if err := ValiderCleSSH(cle); err != nil {
		return Resultat{}, err
	}

	db := database.GetDatabase()
	uid, err := dbusers.Get_User_ID_By_Username(db, cible)
	if err != nil {
		return Resultat{}, fmt.Errorf("utilisateur %q introuvable : %w", cible, err)
	}

	if err := dbusers.AddUserKey(uid, cle, label); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de l'ajout de la clé : %w", err)
	}

	return Resultat{
		Message: fmt.Sprintf(
			"Clé %q ajoutée à %s. Elle permet de se connecter à ce compte sans mot de passe.",
			label, cible),
		Donnees: map[string]string{"username": cible, "label": label},
	}, nil
}

// typeDeCleAccepte vérifie le préfixe d'algorithme.
//
// Le contrôle porte sur le premier champ et non sur un simple HasPrefix de la
// chaîne entière : « ssh-rsaXXXX » commencerait par « ssh-rsa » sans être une
// clé valide, et passerait un contrôle naïf.
func typeDeCleAccepte(cle string) bool {
	champs := strings.Fields(cle)
	if len(champs) < 2 {
		// Une clé se compose au minimum de son type et de son corps encodé.
		return false
	}
	for _, accepte := range typesDeClesAcceptes {
		if champs[0] == accepte {
			return true
		}
	}
	return false
}

// ValiderCleSSH applique à une clé publique les mêmes contrôles que
// « add -u <user> -k ».
//
// Exportée parce que la page /profil n'emprunte PAS le registre, et ne le peut
// pas : modifier son propre profil ne doit pas exiger « write:update:user », qui
// est le droit d'agir sur le compte d'autrui. Elle recopiait donc sa
// validation — et la copie était plus faible que l'originale :
//
//   - deux types acceptés au lieu de sept. Une clé ECDSA ou une clé matérielle
//     (sk-…@openssh.com) était refusée sur le portail et acceptée en ligne de
//     commande, sans que le message dise pourquoi ;
//   - aucun contrôle du saut de ligne. Un fichier de deux lignes déposé sur la
//     page ajoutait DEUX entrées à authorized_keys pour une seule visible dans
//     la liste des clés — la seconde ne se retirerait donc jamais par
//     l'interface.
//
// Une seule définition ferme les deux écarts, et la commande comme la page
// refusent désormais la même chose.
func ValiderCleSSH(cle string) error {
	cle = strings.TrimSpace(cle)
	if cle == "" {
		return fmt.Errorf("clé publique requise")
	}
	if strings.ContainsAny(cle, "\n\r") {
		return fmt.Errorf("clé publique invalide : elle contient un saut de ligne")
	}
	if !typeDeCleAccepte(cle) {
		return fmt.Errorf(
			"clé publique invalide : type non reconnu. Types acceptés : %s",
			strings.Join(typesDeClesAcceptes, ", "))
	}
	return nil
}

func retirerCleUtilisateur(_ Appelant, p Params) (Resultat, error) {
	cible := p.Get("username")
	brut := p.Get("key_id")

	if cible == "" {
		return Resultat{}, fmt.Errorf("utilisateur cible requis")
	}
	if brut == "" {
		return Resultat{}, fmt.Errorf("identifiant de clé requis")
	}
	id, err := strconv.Atoi(brut)
	if err != nil {
		return Resultat{}, fmt.Errorf("identifiant de clé %q invalide : ce n'est pas un nombre", brut)
	}
	if id <= 0 {
		return Resultat{}, fmt.Errorf("identifiant de clé %d invalide", id)
	}

	// La clé appartient-elle bien au compte visé ?
	//
	// DeleteUserKeys supprime par identifiant, sans vérifier le propriétaire.
	// Sans ce contrôle, un délégué autorisé sur « alice » pourrait supprimer
	// une clé de « bob » en devinant son identifiant — un entier, donc facile à
	// parcourir. La portée du droit serait alors sans effet.
	db := database.GetDatabase()
	uid, err := dbusers.Get_User_ID_By_Username(db, cible)
	if err != nil {
		return Resultat{}, fmt.Errorf("utilisateur %q introuvable : %w", cible, err)
	}
	cles, err := dbusers.GetUserKeys(uid)
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des clés de %q impossible : %w", cible, err)
	}
	appartient := false
	for _, k := range cles {
		if k.ID == id {
			appartient = true
			break
		}
	}
	if !appartient {
		return Resultat{}, fmt.Errorf("la clé %d n'appartient pas à %s", id, cible)
	}

	if err := dbusers.DeleteUserKeys([]int{id}); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression de la clé %d : %w", id, err)
	}

	return Resultat{Message: fmt.Sprintf("Clé %d retirée de %s.", id, cible)}, nil
}
