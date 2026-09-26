package action

import (
	"fmt"
	"strings"
	"time"

	"vaultaire/core/auth/passwordpolicy"
	"vaultaire/core/database"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/logs"
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

	saltHex, hashHex, err := hacherMotDePasse(username+"@"+domain, password)
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

	// LE MOT DE PASSE D'UN COMPTE NEUF EST PROVISOIRE — TO-DO 99.
	//
	// Par défaut, et c'est le point : celui qui crée le compte a choisi ce mot de
	// passe, donc il le connaît. Tant qu'il n'a pas été remplacé par son
	// titulaire, ce n'est pas un secret — c'est un laissez-passer partagé entre
	// deux personnes, et la seule chose qui le distingue d'un mot de passe volé
	// est l'intention.
	//
	// La dérogation existe pour les comptes qu'aucune personne n'ouvrira jamais
	// — automatisation, comptes de service — parce que pour eux, « changez-le à
	// la première connexion » n'a pas de titulaire à qui s'adresser.
	provisoire := !estNon(p.Get("temporary"))
	if provisoire {
		if err := passwordpolicy.MarquerProvisoire(database.GetDatabase(),
			username, passwordpolicy.DureeProvisoireDefaut); err != nil {
			// NON BLOQUANT : le compte existe, et le refaire échouerait. Mais
			// c'est un SECURITY, pas un WARNING — un compte censé porter un mot
			// de passe provisoire qui n'en porte pas est exactement ce que ce
			// point corrige.
			logs.Write_Log("SECURITY", fmt.Sprintf(
				"user.create: %s créé mais le drapeau de changement obligatoire n'a pas pu "+
					"être posé (%v) — son mot de passe reste celui choisi par son créateur",
				username, err))
		}
	}

	message := fmt.Sprintf("Utilisateur %s@%s créé.", username, domain)
	if provisoire {
		message += " Son mot de passe est PROVISOIRE : il devra être changé sur le portail" +
			" sous " + passwordpolicy.DureeProvisoireDefaut.String() + "."
	}

	return Resultat{
		Message: message,
		Donnees: map[string]string{
			"username":  username,
			"email":     username + "@" + domain,
			"firstname": firstname,
			"lastname":  lastname,
		},
	}, nil
}

// estNon reconnaît une dérogation explicite.
//
// La valeur par défaut — champ absent — vaut NON : un formulaire qui n'envoie
// pas la case doit produire un compte provisoire, pas l'inverse. Un réglage de
// sécurité dont l'absence ouvre finit toujours par être absent.
func estNon(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "non", "no", "false", "0", "aucun":
		return true
	}
	return false
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

// hacherMotDePasse contrôle la robustesse puis produit le sel et l'empreinte.
//
// Délègue à passwordpolicy.PreparerNouveauMotDePasse, qui enveloppe
// security.Hacher — argon2id — et n'a jamais recopié le calcul.
//
// Le SHA-256 qui vivait ici était l'un des TROIS endroits qui produisaient une
// empreinte, avec le bootstrap de l'administrateur et le changement de mot de
// passe. Trois copies du même calcul, qu'il fallait faire évoluer ensemble sous
// peine de créer des comptes illisibles par les autres chemins. Il n'en reste
// qu'une définition, et elle porte désormais aussi la règle de robustesse
// (TO-DO 100) : un compte ne peut plus NAÎTRE avec « 1234 ».
//
// Le nom du compte est passé parce qu'il fait partie de la règle — un mot de
// passe qui contient l'identifiant est le deuxième que l'attaquant essaie.
func hacherMotDePasse(username, motDePasse string) (selHex, hacheHex string, err error) {
	empreinte, sel, err := passwordpolicy.PreparerNouveauMotDePasse(
		database.GetDatabase(), username, motDePasse)
	if err != nil {
		return "", "", err
	}
	return sel, empreinte, nil
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

	// RÉINITIALISATION PAR UN TIERS : le mot de passe est provisoire (TO-DO 99).
	//
	// C'est le cas d'usage le plus courant du drapeau, et le plus nécessaire :
	// après un dépannage, l'administrateur connaît le mot de passe de quelqu'un
	// d'autre. Sans échéance ni changement obligatoire, il le connaîtrait
	// indéfiniment, et rien ne le dirait au titulaire.
	//
	// Un administrateur qui réinitialise SON PROPRE mot de passe par cette
	// action se marque lui-même — c'est voulu : l'action n'est pas le chemin de
	// changement personnel, qui est le portail et qui lève le drapeau.
	if err := passwordpolicy.MarquerProvisoire(db, cible,
		passwordpolicy.DureeProvisoireDefaut); err != nil {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"user.change_password: mot de passe de %s réinitialisé mais le drapeau de "+
				"changement obligatoire n'a pas pu être posé (%v)", cible, err))
	}

	return Resultat{Message: fmt.Sprintf(
		"Mot de passe de %s changé. Il est PROVISOIRE : %s devra le remplacer sur le "+
			"portail sous %s, après quoi ce mot de passe cesse de fonctionner.",
		cible, cible, passwordpolicy.DureeProvisoireDefaut)}, nil
}
