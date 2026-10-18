package confsys

import "fmt"

// Les règles : quels fichiers, à quelle version, produits comment.
//
// # Monter une version
//
// Un gabarit change → sa règle monte d'une version, son marqueur aussi (dans
// le gabarit ET dans le script), et chaque agent qui démarre avec ce code
// réécrit le fichier sur sa machine. Un fichier marqué d'une version PLUS
// HAUTE que celle que l'agent connaît (après une rétrogradation) n'est pas
// touché : on ne descend pas une configuration.
//
// Non marqué = version 0 : une machine installée avant le 117, ou un fichier
// jamais écrit par Vaultaire. C'est le cas des machines d'avant la 2.2, à qui
// manque KbdInteractiveAuthentication (TO-DO 95) : leur sshd_config passe en
// v1, qui la porte.
const (
	VersionPAM   = 1
	VersionSSHD  = 1
	VersionNSS   = 1
	VersionDconf = 1
)

// Groupes : les fichiers d'un même groupe sont écrits tous ou aucun. Les piles
// PAM ensemble — une pile login branchée et une pile sshd qui ne l'est pas
// feraient deux vérités sur la même machine ; le reste, chacun pour soi :
// une pile gdm personnalisée ne doit pas retenir la correction de sshd_config.
const (
	GroupePAM   = "piles PAM"
	GroupeSSHD  = "sshd_config"
	GroupeNSS   = "nsswitch.conf"
	GroupeDconf = "écran de connexion"
)

// Regle : un fichier tenu.
type Regle struct {
	Nom     string // pour les comptes rendus : « pam.d/sshd »
	Rel     string // sous la racine : « etc/pam.d/sshd »
	Groupe  string
	Version int
	// Requis : absent, c'est un écart. Sinon, absent = rien à tenir, sauf Creer.
	Requis bool
	Creer  bool
	// Produire rend le fichier attendu, à partir de celui en place.
	Produire func(actuel string) (string, error)
	// Verifier contrôle le candidat avant toute écriture (porte de secours).
	Verifier func(candidat string) error
	// ValiderSSHD : « sshd -t -f <candidat> » avant de basculer.
	ValiderSSHD bool
	// Apres : ce qu'il faut relancer quand le fichier a changé.
	Apres string
	// SauvegardeAilleurs : la sauvegarde ne va pas à côté du fichier — dconf
	// compile TOUS les fichiers de gdm.d, sauvegardes comprises.
	SauvegardeAilleurs bool
}

const (
	apresSSHD  = "sshd"
	apresDconf = "dconf"
)

func gabarit(g string) func(string) (string, error) {
	return func(string) (string, error) { return g, nil }
}

func brancher(auth, session string) func(string) (string, error) {
	return func(actuel string) (string, error) { return brancherPileDebian(actuel, auth, session) }
}

// Regles rend les règles d'une famille. avecGDM : /etc/pam.d/gdm-password
// existe — comme les scripts, l'agent ne branche l'écran de connexion
// graphique que là où il y en a un.
func Regles(famille string, avecGDM bool) ([]Regle, error) {
	pile := func(nom string, produire func(string) (string, error), requis bool) Regle {
		return Regle{Nom: "pam.d/" + nom, Rel: "etc/pam.d/" + nom, Groupe: GroupePAM, Version: VersionPAM,
			Requis: requis, Produire: produire, Verifier: VerifierPorteDeSecours}
	}
	var r []Regle
	switch famille {
	case "rocky":
		r = append(r, pile("login", gabarit(pileLoginRocky), true), pile("sshd", gabarit(pileSSHDRocky), true))
		if avecGDM {
			r = append(r, pile("gdm-password", gabarit(pileGDMRocky), true))
		}
	case "debian":
		r = append(r, pile("login", brancher(authLoginDebian, sessionDebian), true),
			pile("sshd", brancher(authSSHDDebian, ""), true))
		if avecGDM {
			r = append(r, pile("gdm-password", brancher(authGDMDebian, sessionDebian), true))
		}
	default:
		return nil, fmt.Errorf("famille %q : aucune configuration connue", famille)
	}
	r = append(r,
		Regle{Nom: "ssh/sshd_config", Rel: "etc/ssh/sshd_config", Groupe: GroupeSSHD, Version: VersionSSHD,
			Requis: true, ValiderSSHD: true, Apres: apresSSHD,
			Produire: func(a string) (string, error) { return reecrireSSHD(a), nil }},
		Regle{Nom: "nsswitch.conf", Rel: "etc/nsswitch.conf", Groupe: GroupeNSS, Version: VersionNSS,
			Requis: true, Produire: brancherNSS},
	)
	if avecGDM {
		r = append(r, Regle{Nom: "dconf gdm.d/10-vaultaire-userlist", Rel: "etc/dconf/db/gdm.d/10-vaultaire-userlist",
			Groupe: GroupeDconf, Version: VersionDconf, Creer: true, Apres: apresDconf, SauvegardeAilleurs: true,
			Produire: gabarit(dconfGDM)})
	}
	return r, nil
}

// ServiceSSH : le nom de l'unité, comme dans les scripts.
func ServiceSSH(famille string) string {
	if famille == "debian" {
		return "ssh"
	}
	return "sshd"
}
