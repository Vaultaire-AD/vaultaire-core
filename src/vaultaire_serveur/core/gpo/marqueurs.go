package gpo

import (
	"fmt"
	"strings"
)

// LES MARQUEURS PAR COMPTE — TO-DO 211.
//
// Un `user_git_config` posait la MÊME valeur à tous les comptes visés :
// `user.name` valait la même chose pour chaque membre du groupe. Les valeurs
// des champs marqués `Marqueurs` acceptent désormais des marqueurs, remplacés
// par l'AGENT au moment d'appliquer, pour chaque compte : la politique signée
// reste la même pour tout le groupe.
//
// Ce paquet n'en remplace aucun. Il les VÉRIFIE, pour qu'un marqueur inconnu
// soit refusé à l'enregistrement de la GPO, sous les yeux de qui l'écrit,
// plutôt que découvert sur un poste. La liste est la même des deux côtés : un
// test jumeau la fige (marqueurs_test.go et gpo/marqueurs_test.go côté agent).
//
// # Pourquoi pas user_cron, file_deploy, user_ssh_client_config
//
// `%` y a déjà un sens : cron le lit comme un saut de ligne, `ssh_config` a
// ses propres marqueurs (`%u` y est l'utilisateur LOCAL, `%r` le distant), et
// un fichier déposé peut légitimement en porter. Y remplacer quoi que ce soit
// changerait des politiques qui fonctionnent.

// MarqueursConnus : le caractère qui suit `%`, et ce qu'il devient.
var MarqueursConnus = map[byte]string{
	'u': "nom du compte, sans domaine (alice)",
	'U': "compte complet (alice@acme.lan)",
	'd': "domaine du compte (acme.lan)",
	'n': "nom complet tiré de l'annuaire (Alice Martin)",
	'm': "adresse de messagerie de l'annuaire",
	'%': "un % littéral",
}

// AideMarqueurs est l'aide affichée sous les champs qui les acceptent.
const AideMarqueurs = "Marqueurs remplacés pour chaque compte : %u (alice), %U (alice@acme.lan), " +
	"%d (acme.lan), %n (nom complet), %m (adresse de messagerie), %% (un %). " +
	"Exemple : user.name = %n, user.email = %m."

// VerifierMarqueurs refuse une valeur qui porte un marqueur inconnu, ou un `%`
// final isolé.
func VerifierMarqueurs(v string) error {
	for i := 0; i < len(v); i++ {
		if v[i] != '%' {
			continue
		}
		if i+1 >= len(v) {
			return fmt.Errorf("« %% » final isolé — écrire %%%% pour un %% littéral")
		}
		if _, ok := MarqueursConnus[v[i+1]]; !ok {
			return fmt.Errorf("marqueur inconnu « %%%c » — connus : %s", v[i+1], listeMarqueurs())
		}
		i++
	}
	return nil
}

func listeMarqueurs() string {
	var l []string
	for _, c := range []byte("uUdnm%") {
		l = append(l, "%"+string(c))
	}
	return strings.Join(l, " ")
}

// Identite est ce que l'agent ne peut pas savoir seul d'un compte : son nom
// complet et son adresse, tirés de l'annuaire. Livrée avec la politique de
// compte (DeliveryPolicy.Identite) — le module NSS de l'agent ne fournit que le
// nom de connexion.
type Identite struct {
	NomComplet string `json:"nom_complet,omitempty"`
	Mail       string `json:"mail,omitempty"`
	Domaine    string `json:"domaine,omitempty"`
}
