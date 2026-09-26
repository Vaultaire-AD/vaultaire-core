package sshclient

import (
	"strings"
	"testing"
)

// Le point 95 tient à une règle et à une migration. La règle s'éprouve sans
// base — c'est pour cela que la décision est séparée de la lecture.

// LE test du point : un compte à second facteur ne passe plus sans code.
//
// C'était le défaut : `grep -rn "mfa\|totp" ducky-network/authentification/`
// ne rendait rien. Un compte marqué `mfa_required` dont le mot de passe fuitait
// était bloqué sur le portail et ouvrait une session SSH sur n'importe quelle
// machine du parc.
func TestUnCompteAvecSecondFacteurNePassePlusSansCode(t *testing.T) {
	// Agent ancien, qui n'envoie aucune ligne « otp: ».
	d, motif := DeciderSecondFacteur(Entree{Actif: true, CodePresent: false})
	if d != MFAReclamer {
		t.Errorf("décision %v pour un agent sans code, attendu MFAReclamer", d)
	}
	if !strings.Contains(motif, "agent") {
		t.Errorf("le motif ne dit pas que l'agent est en cause : %q", motif)
	}

	// Et ce refus ne dépend PAS du réglage de migration : celui-ci décide du
	// sort des comptes ORDINAIRES. Dispenser de second facteur ceux qui l'ont
	// activé reviendrait à désactiver la fonctionnalité pour ses seuls
	// utilisateurs.
	d, _ = DeciderSecondFacteur(Entree{Actif: true, CodePresent: false, ExigenceDucky: false})
	if d != MFAReclamer {
		t.Errorf("décision %v avec la migration en cours : un compte à second facteur "+
			"doit fournir son code dans tous les cas", d)
	}
}

// Avec un code, la décision renvoie à la vérification cryptographique.
func TestUnCodePresentEstEnvoyeALaVerification(t *testing.T) {
	d, _ := DeciderSecondFacteur(Entree{Actif: true, CodePresent: true, Code: "123456"})
	if d != MFAVerifier {
		t.Errorf("décision %v, attendu MFAVerifier", d)
	}

	// Une saisie VIDE n'est pas un code : on la réclame plutôt que de l'envoyer
	// à totp.Validate, qui la refuserait sans dire qu'elle était vide.
	d, motif := DeciderSecondFacteur(Entree{Actif: true, CodePresent: true, Code: ""})
	if d != MFAReclamer {
		t.Errorf("décision %v pour une saisie vide, attendu MFAReclamer", d)
	}
	if !strings.Contains(motif, "saisi") {
		t.Errorf("le motif ne distingue pas la saisie vide : %q", motif)
	}
}

// LA CONVENTION « 0000 ».
//
// Le code voyage sur toutes les ouvertures de session, y compris celles des
// comptes qui n'ont pas de second facteur. « 0000 » est la seule valeur
// acceptée pour ces comptes-là.
func TestLaConventionZeroQuatreFois(t *testing.T) {
	sans := Entree{Actif: false, CodePresent: true}

	sans.Code = CodeSansSecondFacteur
	if d, _ := DeciderSecondFacteur(sans); d != MFAPasser {
		t.Errorf("« %s » refusé pour un compte sans second facteur", CodeSansSecondFacteur)
	}

	// Un VRAI code pour un compte qui n'en a pas : refusé, pas ignoré.
	//
	// C'est le signal soit d'un agent qui se trompe de compte, soit de quelqu'un
	// qui sonde la porte. L'ignorer masquerait les deux.
	sans.Code = "123456"
	d, motif := DeciderSecondFacteur(sans)
	if d != MFARefuser {
		t.Errorf("décision %v : un code envoyé pour un compte sans second facteur "+
			"doit être refusé, pas ignoré", d)
	}
	if !strings.Contains(motif, "qui n'en a pas") {
		t.Errorf("motif peu clair : %q", motif)
	}
}

// LA MIGRATION : sans le réglage, un agent ancien passe ; avec, il est refusé.
//
// Sans ce dispositif, la mise à jour du core couperait l'accès à tout le parc
// d'un coup — y compris à la machine depuis laquelle on administre.
func TestLaMigrationSeDecideParLeReglage(t *testing.T) {
	ancien := Entree{Actif: false, CodePresent: false}

	if d, _ := DeciderSecondFacteur(ancien); d != MFAPasser {
		t.Error("un agent ancien est refusé alors que la migration n'est pas activée — " +
			"la mise à jour du core couperait tout le parc")
	}

	ancien.ExigenceDucky = true
	d, motif := DeciderSecondFacteur(ancien)
	if d != MFAReclamer {
		t.Errorf("décision %v : l'exigence activée doit refuser un agent qui n'envoie "+
			"aucun code", d)
	}
	if !strings.Contains(motif, CleMFADuckyExigee) {
		t.Errorf("le motif ne nomme pas le réglage en cause : %q", motif)
	}
}

// Une exigence de GROUPE sur un compte qui n'a rien enrôlé : refus, et le motif
// dit où aller.
//
// Le laisser passer viderait l'exigence de groupe de son sens sur le chemin le
// plus utilisé du produit — celui des ouvertures de session.
func TestUneExigenceDeGroupeNonEnroleeRefuse(t *testing.T) {
	d, motif := DeciderSecondFacteur(Entree{
		Actif: false, ExigeParGroupe: true, CodePresent: true, Code: CodeSansSecondFacteur,
	})
	if d != MFARefuser {
		t.Errorf("décision %v : un groupe impose le second facteur, le compte ne l'a "+
			"pas enrôlé", d)
	}
	if !strings.Contains(motif, "profil") {
		t.Errorf("le motif ne dit pas où enrôler : %q", motif)
	}
}

// Le code se lit EN QUEUE et par PRÉFIXE, jamais par rang.
//
// Les deux premières lignes du contenu gardent leur position : un core resté à
// l'ancienne version les lit à l'identique et ignore le reste, au lieu de
// prendre le code pour autre chose.
func TestLeCodeSeLitParPrefixe(t *testing.T) {
	code, present := LireCodeOTP([]string{"otp:123456"})
	if !present || code != "123456" {
		t.Errorf("code = %q, present = %v", code, present)
	}

	// Mélangé à d'autres lignes de queue, dans n'importe quel ordre.
	code, present = LireCodeOTP([]string{"groups:a,b", "otp:654321", "notice:coucou"})
	if !present || code != "654321" {
		t.Errorf("code = %q parmi d'autres lignes préfixées", code)
	}

	// ABSENTE : c'est un agent ancien, et ce n'est pas la même chose qu'une
	// ligne présente et vide. Toute la migration tient à cette distinction.
	code, present = LireCodeOTP([]string{"groups:a"})
	if present {
		t.Errorf("une ligne absente est rendue présente (code %q)", code)
	}

	// PRÉSENTE ET VIDE : un agent à jour dont l'utilisateur n'a rien tapé.
	code, present = LireCodeOTP([]string{"otp:"})
	if !present || code != "" {
		t.Errorf("ligne vide : code = %q, present = %v", code, present)
	}

	// Les espaces autour sont retirés : une invite PAM peut en laisser.
	code, _ = LireCodeOTP([]string{"otp:  123456  "})
	if code != "123456" {
		t.Errorf("code non nettoyé : %q", code)
	}
}

// Une ligne démesurée est tronquée, pas transmise telle quelle.
//
// La décision de refuser appartient à la vérification, qui sait dire pourquoi ;
// tronquer garantit seulement qu'une ligne de mille caractères ne traverse pas
// la suite.
func TestUneLigneDemesureeEstBornee(t *testing.T) {
	long := strings.Repeat("9", 500)
	code, present := LireCodeOTP([]string{"otp:" + long})
	if !present {
		t.Fatal("ligne non reconnue")
	}
	if len(code) != LongueurMaxOTP {
		t.Errorf("code de %d caractères, attendu %d", len(code), LongueurMaxOTP)
	}
}

// Le préfixe est le MÊME que côté agent. Les deux vivent dans des modules Go
// distincts : rien ne peut les tenir liés à la compilation, et les faire
// diverger d'un caractère ferait ignorer le code par le core — donc refuser la
// session d'un compte à second facteur, sans qu'aucun message ne dise pourquoi.
func TestLePrefixeEstCeluiDuProtocole(t *testing.T) {
	if PrefixeOTP != "otp:" {
		t.Errorf("PrefixeOTP = %q : l'agent Linux et la tuile Windows écrivent « otp: »",
			PrefixeOTP)
	}
	if CodeSansSecondFacteur != "0000" {
		t.Errorf("CodeSansSecondFacteur = %q : c'est ce que disent l'invite PAM et le "+
			"libellé du champ Windows", CodeSansSecondFacteur)
	}
}

// Le tableau complet de la règle, cas par cas.
//
// Écrit comme un tableau parce que c'est ainsi qu'on le relit : huit
// combinaisons de trois booléens, dont chacune a une raison d'être ce qu'elle
// est. Un défaut ici ouvre ou ferme une porte sans que rien d'autre ne le voie.
func TestLeTableauCompletDeLaRegle(t *testing.T) {
	cas := []struct {
		nom     string
		entree  Entree
		attendu Decision
	}{
		{"compte ordinaire, agent ancien, migration en cours",
			Entree{}, MFAPasser},
		{"compte ordinaire, agent ancien, migration activée",
			Entree{ExigenceDucky: true}, MFAReclamer},
		{"compte ordinaire, code 0000",
			Entree{CodePresent: true, Code: "0000"}, MFAPasser},
		{"compte ordinaire, code 0000, migration activée",
			Entree{CodePresent: true, Code: "0000", ExigenceDucky: true}, MFAPasser},
		{"compte ordinaire, vrai code",
			Entree{CodePresent: true, Code: "123456"}, MFARefuser},
		{"compte à second facteur, agent ancien",
			Entree{Actif: true}, MFAReclamer},
		{"compte à second facteur, code fourni",
			Entree{Actif: true, CodePresent: true, Code: "123456"}, MFAVerifier},
		{"compte à second facteur, code 0000",
			Entree{Actif: true, CodePresent: true, Code: "0000"}, MFAVerifier},
		{"groupe exigeant, compte non enrôlé",
			Entree{ExigeParGroupe: true, CodePresent: true, Code: "0000"}, MFARefuser},
		{"groupe exigeant, compte enrôlé",
			Entree{Actif: true, ExigeParGroupe: true, CodePresent: true, Code: "123456"}, MFAVerifier},
	}

	for _, c := range cas {
		if d, motif := DeciderSecondFacteur(c.entree); d != c.attendu {
			t.Errorf("%s : décision %v, attendu %v (%s)", c.nom, d, c.attendu, motif)
		}
	}
}

// Le cas « compte à second facteur, code 0000 » mérite d'être dit : il part à la
// vérification, où totp.Validate le refusera.
//
// C'est volontaire. Accepter « 0000 » ici parce que « c'est la valeur des
// comptes sans second facteur » ouvrirait une porte universelle : il suffirait
// de taper 0000 pour contourner le second facteur de n'importe qui.
func TestZeroQuatreFoisNeContournePasUnSecondFacteurActif(t *testing.T) {
	d, _ := DeciderSecondFacteur(Entree{
		Actif: true, CodePresent: true, Code: CodeSansSecondFacteur,
	})
	if d == MFAPasser {
		t.Fatal("« 0000 » fait passer un compte à second facteur : c'est une porte " +
			"universelle, il suffirait de le taper pour contourner le MFA de n'importe qui")
	}
	if d != MFAVerifier {
		t.Errorf("décision %v, attendu MFAVerifier — c'est totp.Validate qui doit le refuser", d)
	}
}
