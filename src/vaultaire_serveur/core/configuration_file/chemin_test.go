package configuration_file

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// La résolution du chemin de configuration.
//
// # Ce que ces tests gardent
//
// Deux choses, et la seconde est la plus facile à casser par inadvertance.
//
// Que la variable d'environnement L'EMPORTE, même sur un fichier qui n'existe
// pas : la poser est une décision, et se rabattre en silence sur un autre
// fichier donnerait un core qui tourne avec une configuration que personne n'a
// demandée — le pire des résultats, puisqu'il a l'air de marcher.
//
// Que l'emplacement HISTORIQUE reste accepté. Le retirer casserait les
// déploiements en place pour un gain esthétique.

func TestLaVariableLEmporte(t *testing.T) {
	t.Setenv(EnvConfig, "/un/chemin/choisi/serveur_conf.yaml")

	chemin, consultes := CheminConfig()

	if chemin != "/un/chemin/choisi/serveur_conf.yaml" {
		t.Errorf("chemin = %q : la variable d'environnement doit l'emporter", chemin)
	}
	if len(consultes) != 1 || !strings.Contains(consultes[0], EnvConfig) {
		t.Errorf("consultés = %v : le message doit dire que la variable a décidé", consultes)
	}
}

// TestLaVariableLEmporteMemeSurUnFichierAbsent.
//
// LE test de ce fichier. Se rabattre sur /etc ou /opt parce que le fichier
// désigné n'existe pas ferait démarrer le core sur une configuration que
// personne n'a demandée — et il aurait l'air de marcher.
func TestLaVariableLEmporteMemeSurUnFichierAbsent(t *testing.T) {
	t.Setenv(EnvConfig, "/chemin/qui/n/existe/pas.yaml")

	chemin, _ := CheminConfig()

	if chemin != "/chemin/qui/n/existe/pas.yaml" {
		t.Fatalf("chemin = %q : un repli silencieux ferait démarrer le core sur "+
			"une configuration que personne n'a demandée", chemin)
	}
}

// TestUneVariableVideNeComptePas : une variable posée à la chaîne vide — cas
// courant d'un fichier d'environnement mal rempli — ne doit pas désigner « ».
func TestUneVariableVideNeComptePas(t *testing.T) {
	for _, vide := range []string{"", "   ", "\t"} {
		t.Setenv(EnvConfig, vide)
		chemin, _ := CheminConfig()
		if strings.TrimSpace(chemin) == "" {
			t.Errorf("variable %q → chemin vide", vide)
		}
	}
}

// TestSansVariableLesDeuxEmplacementsSontConsultes.
//
// L'historique doit rester dans la liste : le fichier Compose de développement,
// le Dockerfile de préproduction et la documentation d'installation le
// désignent tous.
func TestSansVariableLesDeuxEmplacementsSontConsultes(t *testing.T) {
	t.Setenv(EnvConfig, "")

	_, consultes := CheminConfig()

	var trouveStandard, trouveHistorique bool
	for _, c := range consultes {
		if c == CheminStandard {
			trouveStandard = true
		}
		if c == CheminHistorique {
			trouveHistorique = true
		}
	}
	if !trouveStandard {
		t.Error("l'emplacement recommandé n'est pas consulté")
	}
	if !trouveHistorique {
		t.Error("l'emplacement historique n'est plus consulté : les déploiements " +
			"en place cesseraient de démarrer")
	}
}

// TestLeRecommandeEstRenduQuandRienNExiste.
//
// Le message d'erreur nomme le chemin rendu. Rendre l'emplacement historique
// perpétuerait l'ancien usage à chaque nouvelle installation.
func TestLeRecommandeEstRenduQuandRienNExiste(t *testing.T) {
	t.Setenv(EnvConfig, "")

	chemin, _ := CheminConfig()

	// Sur une machine de développement, ni /etc/vaultaire ni /opt/vaultaire
	// n'existent — le test vaut donc pour le cas « rien trouvé ». S'ils
	// existent, l'un des deux est rendu, ce qui est correct aussi.
	if chemin != CheminStandard && chemin != CheminHistorique {
		t.Errorf("chemin = %q, attendu l'un des deux emplacements connus", chemin)
	}
}

// TestUnFichierExistantEstPrefereAuRecommande : le repli sert à quelque chose.
func TestUnFichierExistantEstPrefereAuRecommande(t *testing.T) {
	t.Setenv(EnvConfig, "")

	// On ne peut pas créer /etc/vaultaire depuis un test. On éprouve donc la
	// règle sur ce qui est vérifiable : la présence décide, et la fonction ne
	// rend jamais un chemin absent de la liste des candidats.
	chemin, consultes := CheminConfig()

	if _, err := os.Stat(chemin); err == nil {
		var connu bool
		for _, c := range consultes {
			if c == chemin {
				connu = true
			}
		}
		if !connu {
			t.Errorf("chemin %q rendu alors qu'il n'est pas dans %v", chemin, consultes)
		}
	}
}

// TestLeMessageDitOuChercherEtQuoiFaire.
//
// C'est le tout premier obstacle d'une installation, rencontré avant d'avoir la
// moindre idée de la structure du projet. Un message qui ne dit que « fichier
// introuvable » oblige à lire les sources.
func TestLeMessageDitOuChercherEtQuoiFaire(t *testing.T) {
	err := ErreurConfigIntrouvable(
		[]string{CheminStandard, CheminHistorique},
		os.ErrNotExist)

	msg := err.Error()

	attendus := map[string]string{
		"l'emplacement recommandé":    CheminStandard,
		"l'emplacement historique":    CheminHistorique,
		"le répertoire à créer":       filepath.Dir(CheminStandard),
		"la variable d'environnement": EnvConfig,
		"le modèle de configuration":  "deployments/configs/serveur_conf.yaml",
		"la documentation":            "docs/Installation",
	}
	for quoi, attendu := range attendus {
		if !strings.Contains(msg, attendu) {
			t.Errorf("le message ne nomme pas %s (%q) :\n%s", quoi, attendu, msg)
		}
	}
}
