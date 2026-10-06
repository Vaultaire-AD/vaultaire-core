package configuration_file

import (
	"os"
	"strings"
	"testing"

	"vaultaire/core/storage"
)

// Le point 99 tient à deux refus et à une détection. Aucun des trois n'a besoin
// de base : ils portent sur la configuration, c'est-à-dire sur du texte et des
// variables lues avant que quoi que ce soit ne s'ouvre.

func avecConfigAdmin(t *testing.T, actif bool, motDePasse string) {
	t.Helper()
	enableAvant, mdpAvant := storage.Administrateur_Enable, storage.Administrateur_Password
	storage.Administrateur_Enable, storage.Administrateur_Password = actif, motDePasse
	t.Cleanup(func() {
		storage.Administrateur_Enable, storage.Administrateur_Password = enableAvant, mdpAvant
	})
}

// LE test du point : le serveur ne démarre pas sur le mot de passe du dépôt.
//
// Ce compte entre dans le groupe `vaultaire` — tous les droits, sur tous les
// domaines — et son mot de passe est publié dans le dépôt Git du produit. Une
// installation faite depuis les fichiers livrés, sans les retoucher, l'exposait.
func TestLeServeurRefuseDeDemarrerSurLeMotDePasseDuDepot(t *testing.T) {
	for _, demo := range []string{"admin123", "password", "changeme", "CHANGEZ_MOI"} {
		avecConfigAdmin(t, true, demo)
		err := VerifierValeursLivrees()
		if err == nil {
			t.Errorf("le serveur démarre avec le mot de passe de démonstration %q", demo)
			continue
		}
		// Le message doit dire QUOI FAIRE : il arrive devant quelqu'un qui
		// installe, et qui n'a aucun autre moyen d'apprendre ce qui est refusé.
		if !strings.Contains(err.Error(), "VAULTAIRE_ADMIN_PASSWORD") {
			t.Errorf("le refus ne dit pas comment corriger : %q", err)
		}
	}
}

// Un mot de passe vide est le DÉFAUT DU CODE, c'est-à-dire « la configuration
// ne dit rien ». Il doit s'arrêter ici, avant l'ouverture de la base — et non à
// l'amorçage, qui a lieu après le démarrage du service Ducky.
func TestUnMotDePasseAbsentArreteLeDemarrage(t *testing.T) {
	for _, vide := range []string{"", "   ", "\t"} {
		avecConfigAdmin(t, true, vide)
		err := VerifierValeursLivrees()
		if err == nil {
			t.Errorf("le serveur démarre sans mot de passe d'amorçage (%q)", vide)
			continue
		}
		// Le piège le plus probable est l'orthographe de la section : le message
		// doit la nommer, sinon on cherche du côté du mot de passe.
		if !strings.Contains(err.Error(), "administreur") {
			t.Errorf("le refus ne mentionne pas l'orthographe de la section : %q", err)
		}
	}
}

// Un mot de passe choisi passe : un test de refus seul serait satisfait par une
// fonction qui refuse tout, et le serveur ne démarrerait jamais.
func TestUnMotDePasseChoisiLaisseDemarrer(t *testing.T) {
	avecConfigAdmin(t, true, "correcte agrafe batterie")
	if err := VerifierValeursLivrees(); err != nil {
		t.Errorf("un mot de passe choisi est refusé : %v", err)
	}
}

// Un serveur qui ne crée aucun compte d'amorçage n'a pas de mot de passe à
// vérifier. Sans cette sortie, `administrateur.enable: false` — la
// configuration d'un second core de cluster — l'empêcherait de démarrer.
func TestSansCompteDAmorcageRienNEstExige(t *testing.T) {
	avecConfigAdmin(t, false, "")
	if err := VerifierValeursLivrees(); err != nil {
		t.Errorf("un serveur sans compte d'amorçage est refusé : %v", err)
	}
}

// LA DÉTECTION : l'ancienne orthographe de la section.
//
// `administreur:` n'a JAMAIS été lue — l'étiquette Go dit `administrateur`, et
// un décodeur YAML apparie sur l'étiquette exacte. Toute la section était donc
// ignorée en silence, et le défaut restait invisible parce que les valeurs par
// défaut du code étaient identiques à celles du fichier livré.
//
// Corriger le fichier sans cette détection aurait remplacé un silence par un
// autre : les installations qui ont recopié l'ancien fichier seraient reparties
// sur les valeurs par défaut, sans message.
func TestLAncienneOrthographeEstNommee(t *testing.T) {
	yaml := "web:\n  port: 443\n\nadministreur:\n  enable: true\n  username: admin\n"

	err := SignalerCleMalOrthographiee([]byte(yaml))
	if err == nil {
		t.Fatal("la section « administreur: » passe inaperçue — c'est le défaut d'origine")
	}
	for _, attendu := range []string{"administreur", "administrateur"} {
		if !strings.Contains(err.Error(), attendu) {
			t.Errorf("le message ne nomme pas %q : %q", attendu, err)
		}
	}
}

// La bonne orthographe ne déclenche rien, y compris quand le mot apparaît
// ailleurs dans le fichier.
func TestLaBonneOrthographeNeDeclencheRien(t *testing.T) {
	cas := map[string]string{
		"section correcte":        "administrateur:\n  enable: true\n",
		"mot dans un commentaire": "# administreur : ancienne orthographe, ne plus employer\nweb:\n  port: 443\n",
		"fichier vide":            "",
		"valeur qui y ressemble":  "web:\n  titre: \"espace administreur\"\n",
	}
	for nom, yaml := range cas {
		if err := SignalerCleMalOrthographiee([]byte(yaml)); err != nil {
			t.Errorf("%s : refusé à tort (%v)", nom, err)
		}
	}
}

// Les marqueurs du fichier livré se reconnaissent : ils ne doivent jamais
// fonctionner comme des valeurs.
func TestLesMarqueursSeReconnaissent(t *testing.T) {
	if !Marqueur("CHANGEZ_MOI") || !Marqueur("CHANGEZ_MOI_mot_de_passe") {
		t.Error("un marqueur du fichier livré n'est pas reconnu")
	}
	if Marqueur("correcte agrafe batterie") {
		t.Error("une valeur ordinaire est prise pour un marqueur")
	}
}

// LE test-sentinelle du dépôt : le fichier LIVRÉ ne porte aucune valeur qui
// fonctionne.
//
// # Pourquoi il vit ici
//
// Les deux fonctions ci-dessus refusent au DÉMARRAGE, ce qui protège
// l'exploitant. Celui-ci protège le DÉPÔT : il échoue le jour où quelqu'un
// remet une valeur commode dans le fichier publié « juste pour la démo », et il
// échoue AVANT que ce fichier ne soit copié dans une image.
//
// C'est le même geste que le point 99 corrige, et rien n'empêchait de le
// refaire.
func TestLeFichierLivreNePorteAucuneValeurQuiFonctionne(t *testing.T) {
	const chemin = "../../../../deployments/configs/serveur_conf.yaml"

	contenu, err := os.ReadFile(chemin)
	if err != nil {
		// Le fichier est dans le dépôt, pas dans le module : un module extrait
		// seul ne l'a pas. On le dit plutôt que d'échouer.
		t.Skipf("fichier livré introuvable (%v) — vérification ignorée", err)
	}

	// L'ancienne orthographe doit avoir disparu du fichier lui-même, sans quoi
	// le core refuserait de démarrer sur sa propre configuration livrée.
	if err := SignalerCleMalOrthographiee(contenu); err != nil {
		t.Errorf("le fichier livré porte encore l'ancienne orthographe : %v", err)
	}

	for _, ligne := range strings.Split(string(contenu), "\n") {
		nue := strings.TrimSpace(ligne)
		if strings.HasPrefix(nue, "#") {
			continue
		}
		cle, valeur, coupe := strings.Cut(nue, ":")
		if !coupe || !strings.Contains(strings.ToLower(cle), "password") {
			continue
		}
		valeur = strings.Trim(strings.TrimSpace(valeur), `"'`)
		if valeur == "" {
			continue
		}
		if !Marqueur(valeur) {
			t.Errorf("le fichier livré porte un mot de passe qui fonctionne : « %s ».\n"+
				"  Un fichier publié dans le dépôt Git ne doit contenir que des marqueurs\n"+
				"  CHANGEZ_MOI : toute valeur qui marche reste en place sur chaque\n"+
				"  installation que personne n'a retouchée, et elle est lisible par qui a\n"+
				"  lu le dépôt. C'est exactement le TO-DO 99.", nue)
		}
	}
}
