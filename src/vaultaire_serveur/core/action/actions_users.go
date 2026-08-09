package action

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"vaultaire/core/database"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/tools"
)

// Actions sur les comptes utilisateur.
//
// # Ce que ce fichier réconcilie
//
// Chacune de ces actions existait en DEUX exemplaires — un dans command_create,
// un dans web_admin_pages.go — et les deux avaient divergé. Le relevé, avant
// portage :
//
//	                    ligne de commande        interface web
//	date de naissance   acceptée telle quelle    validée (jj/mm/aaaa)
//	mot de passe vide   accepté                  refusé
//	prénom / nom        déduits de « a.b »       jamais déduits
//	nom réservé         refusé                   refusé
//
// Aucune des deux n'était fausse ; c'est leur coexistence qui l'était. Le même
// formulaire rempli à l'identique produisait deux comptes différents selon la
// porte empruntée, et une correction n'en réparait jamais qu'une moitié.
//
// Règle appliquée : LE PLUS STRICT DES DEUX GAGNE. Une validation présente d'un
// côté n'est jamais perdue.
//
// Conséquence à connaître : `vlt create -u alice paris.fr motdepasse 32/13/1990`
// passait et sera désormais refusé. C'est une correction — la date était écrite
// telle quelle en base — mais elle change un comportement existant.

// EnregistrerActionsUtilisateur ajoute les actions de ce fichier au registre.
//
// Enregistrement explicite plutôt que init() : l'ordre d'initialisation entre
// paquets dépendrait alors de l'ordre des imports, et un import retiré par
// mégarde ferait disparaître des actions sans erreur de compilation. Ici, une
// action absente vient d'un appel absent, visible à la lecture.
func EnregistrerActionsUtilisateur(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "user.create",
		CleRBAC: "write:create:user",
		// Création : la cible n'existe pas encore, elle n'a donc aucun domaine
		// dont on pourrait déduire une portée. Le droit global est exigé.
		Portee:   PorteeGlobale,
		Resume:   "crée un compte utilisateur",
		Executer: creerUtilisateur,
	})

	r.MustEnregistrer(Definition{
		Nom:      "user.update",
		CleRBAC:  "write:update:user",
		Portee:   PorteeUtilisateur,
		Resume:   "modifie l'identifiant, le prénom ou le nom d'un compte",
		Executer: modifierUtilisateur,
	})

	r.MustEnregistrer(Definition{
		Nom:      "user.change_password",
		CleRBAC:  "write:update:user",
		Portee:   PorteeUtilisateur,
		Resume:   "change le mot de passe d'un compte",
		Executer: changerMotDePasse,
	})
}

// nomsReserves liste les identifiants que le service s'attribue.
//
// En minuscules, et la comparaison l'est aussi : « Vaultaire » et « VAULTAIRE »
// désignent le même compte pour la base, mais passeraient une comparaison
// littérale. Le compte de service serait alors doublé par un compte ordinaire
// portant le même nom aux yeux de tout ce qui compare sans distinction de casse.
var nomsReserves = map[string]bool{
	"vaultaire": true,
	"root":      true,
}

// creerUtilisateur applique les validations des DEUX anciennes versions.
func creerUtilisateur(_ Appelant, p Params) (Resultat, error) {
	username := p.Get("username")
	domain := p.Get("domain")
	password := p.Brut("password") // brut : rogner un mot de passe empêcherait
	// l'utilisateur de se connecter avec ce qu'il a saisi.
	birthdate := p.Get("birthdate")
	firstname := p.Get("firstname")
	lastname := p.Get("lastname")

	if username == "" || domain == "" {
		return Resultat{}, fmt.Errorf("identifiant et domaine requis")
	}
	// Venait du web seulement. La ligne de commande acceptait un mot de passe
	// vide, ce qui produisait un compte dont le haché était celui de la chaîne
	// vide — utilisable par quiconque le devinait.
	if password == "" {
		return Resultat{}, fmt.Errorf("mot de passe requis")
	}
	if nomsReserves[strings.ToLower(username)] {
		return Resultat{}, fmt.Errorf("identifiant %q réservé par le service", username)
	}
	// Le « : » est le séparateur de /etc/passwd et de la carte des identifiants
	// lue par le module NSS. Un nom qui en contient y fabriquerait une seconde
	// entrée à partir d'une seule.
	if strings.ContainsAny(username, ":\n\r/@") {
		return Resultat{}, fmt.Errorf("identifiant %q invalide : caractères interdits (: / @ et sauts de ligne)", username)
	}

	// Venait du web seulement. La commande écrivait la chaîne telle quelle en
	// base, sans jamais vérifier qu'elle représentait une date.
	if birthdate != "" {
		if _, err := tools.StringToDate(birthdate); err != nil {
			return Resultat{}, fmt.Errorf("date de naissance invalide : %w", err)
		}
	}

	// Venait de la ligne de commande seulement : « jean.dupont » donne prénom
	// « jean » et nom « dupont ». Le web laissait les deux champs à
	// l'identifiant complet.
	if firstname == "" || lastname == "" {
		deduitPrenom, deduitNom := deduireIdentite(username)
		if firstname == "" {
			firstname = deduitPrenom
		}
		if lastname == "" {
			lastname = deduitNom
		}
	}

	saltHex, hashHex, err := hacherMotDePasse(password)
	if err != nil {
		return Resultat{}, err
	}

	err = dbusers.Create_New_User(
		database.GetDatabase(),
		username, firstname, lastname,
		username+"@"+domain,
		hashHex, saltHex, birthdate,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la création : %w", err)
	}

	return Resultat{
		Message: fmt.Sprintf("Utilisateur %s@%s créé.", username, domain),
		Donnees: map[string]string{
			"username":  username,
			"email":     username + "@" + domain,
			"firstname": firstname,
			"lastname":  lastname,
		},
	}, nil
}

// deduireIdentite sépare « jean.dupont » en prénom et nom.
//
// SplitN à 2 et non Split : « jean.pierre.dupont » donne alors prénom
// « jean » et nom « pierre.dupont ». Un Split simple aurait rendu trois
// morceaux dont le troisième aurait été perdu en silence — le nom de famille
// amputé, sans que rien ne le signale.
func deduireIdentite(username string) (prenom, nom string) {
	if !strings.Contains(username, ".") {
		return username, username
	}
	parts := strings.SplitN(username, ".", 2)
	if parts[0] == "" || parts[1] == "" {
		// « .dupont » ou « jean. » : un point mal placé ne doit pas produire un
		// prénom vide.
		return username, username
	}
	return parts[0], parts[1]
}

// hacherMotDePasse produit le sel et le haché stockés en base.
//
// Reprend exactement le calcul des deux anciennes versions — SHA-256 de
// sel‖mot de passe — pour que les comptes existants restent utilisables.
//
// Ce n'est pas une validation de ce choix : il est discuté ailleurs. Le
// modifier ici, au passage d'une refonte de structure, invaliderait tous les
// mots de passe du parc sans que ce soit la question du jour.
func hacherMotDePasse(motDePasse string) (selHex, hacheHex string, err error) {
	sel := make([]byte, 16)
	if _, err := rand.Read(sel); err != nil {
		return "", "", fmt.Errorf("erreur lors de la génération du sel : %w", err)
	}
	sale := append(append([]byte{}, sel...), []byte(motDePasse)...)
	somme := sha256.Sum256(sale)
	return hex.EncodeToString(sel), hex.EncodeToString(somme[:]), nil
}

// modifierUtilisateur change identifiant, prénom ou nom.
//
// Les champs absents ne sont pas touchés — d'où Presente plutôt que Get : un
// formulaire qui n'envoie pas « firstname » ne doit pas l'effacer, alors qu'un
// formulaire qui l'envoie vide le veut vide.
//
// L'ancienne version web passait systématiquement les trois valeurs du
// formulaire ; un formulaire partiel écrasait donc les champs qu'il ne portait
// pas.
func modifierUtilisateur(_ Appelant, p Params) (Resultat, error) {
	cible := p.Get("username")
	if cible == "" {
		return Resultat{}, fmt.Errorf("utilisateur cible requis")
	}

	db := database.GetDatabase()
	courant, err := dbusers.Command_GET_UserInfo(db, cible)
	if err != nil || courant == nil {
		return Resultat{}, fmt.Errorf("utilisateur %q introuvable", cible)
	}
	uid, err := dbusers.Get_User_ID_By_Username(db, cible)
	if err != nil {
		return Resultat{}, fmt.Errorf("utilisateur %q introuvable : %w", cible, err)
	}

	nouveauNom := courant.Username
	if p.Presente("new_username") && p.Get("new_username") != "" {
		nouveauNom = p.Get("new_username")
		if nomsReserves[strings.ToLower(nouveauNom)] {
			return Resultat{}, fmt.Errorf("identifiant %q réservé par le service", nouveauNom)
		}
		if strings.ContainsAny(nouveauNom, ":\n\r/@") {
			return Resultat{}, fmt.Errorf("identifiant %q invalide : caractères interdits", nouveauNom)
		}
	}

	prenom := courant.Firstname
	if p.Presente("firstname") {
		prenom = p.Get("firstname")
	}
	nom := courant.Lastname
	if p.Presente("lastname") {
		nom = p.Get("lastname")
	}

	// Mot de passe et date vides : Update_User_Info les interprète comme
	// « ne pas changer ». Cette action ne touche pas au mot de passe — c'est le
	// rôle de user.change_password, qui exige de le nommer explicitement.
	if err := dbusers.Update_User_Info(db, uid, nouveauNom, prenom, nom, "", ""); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la mise à jour : %w", err)
	}

	message := fmt.Sprintf("Profil de %s mis à jour.", cible)
	if nouveauNom != cible {
		message = fmt.Sprintf("Profil mis à jour, %s renommé en %s.", cible, nouveauNom)
	}
	return Resultat{
		Message: message,
		Donnees: map[string]string{
			"username":  nouveauNom,
			"firstname": prenom,
			"lastname":  nom,
		},
	}, nil
}

// changerMotDePasse remplace le mot de passe d'un compte.
//
// Action distincte de user.update, alors que la base les traite par le même
// appel. La séparation tient à ce que les deux ne se surveillent pas de la même
// façon : « qui a changé le mot de passe de qui » est une question d'audit
// courante, et elle devient illisible si l'opération se confond avec un
// changement de prénom dans les journaux.
func changerMotDePasse(_ Appelant, p Params) (Resultat, error) {
	cible := p.Get("username")
	motDePasse := p.Brut("password")

	if cible == "" {
		return Resultat{}, fmt.Errorf("utilisateur cible requis")
	}
	if motDePasse == "" {
		return Resultat{}, fmt.Errorf("mot de passe requis")
	}

	db := database.GetDatabase()
	courant, err := dbusers.Command_GET_UserInfo(db, cible)
	if err != nil || courant == nil {
		return Resultat{}, fmt.Errorf("utilisateur %q introuvable", cible)
	}
	uid, err := dbusers.Get_User_ID_By_Username(db, cible)
	if err != nil {
		return Resultat{}, fmt.Errorf("utilisateur %q introuvable : %w", cible, err)
	}

	// Les autres champs sont repris tels quels : Update_User_Info les écrit
	// tous, et leur passer des valeurs vides effacerait prénom et nom au
	// passage. L'ancienne version web faisait déjà cette lecture préalable ;
	// c'est la raison pour laquelle elle est conservée.
	if err := dbusers.Update_User_Info(db, uid,
		courant.Username, courant.Firstname, courant.Lastname, motDePasse, ""); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors du changement de mot de passe : %w", err)
	}

	return Resultat{Message: fmt.Sprintf("Mot de passe de %s changé.", cible)}, nil
}
