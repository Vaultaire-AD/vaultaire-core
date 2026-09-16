package action

import (
	"strings"
	"testing"
)

// Validation des enregistrements DNS.
//
// # Le défaut que ces tests figent
//
// `validateDNSRecordInput` vivait dans command_dns. Le portage des actions DNS
// l'a laissée derrière : le fichier est resté, sans plus aucun appelant, et un
// balayage des fonctions orphelines a fini par le montrer — plusieurs lots plus
// tard.
//
// Entre-temps, `dns record add www A pas-une-ip` était accepté. La donnée
// partait en base, et l'enregistrement ne résolvait rien.
//
// C'est le pire genre de défaut : la ligne EXISTE dans la table, le
// comportement n'est pas là, et rien ne relie les deux. Le symptôme observé —
// « ce nom ne résout pas » — arrive des jours plus tard, sur une machine, et
// n'oriente vers rien.

func TestTypeInconnuRefuse(t *testing.T) {
	err := donneeDNSAcceptable("AAAA", "www.exemple.fr", "::1")
	if err == nil {
		t.Fatal("un type non pris en charge a été accepté — il s'écrirait en base " +
			"pour n'être jamais servi")
	}
	if !strings.Contains(err.Error(), "AAAA") {
		t.Errorf("message %q : ne nomme pas le type refusé", err)
	}
	// Le message doit lister les types acceptés : sans cela, l'utilisateur
	// doit deviner ou lire le code.
	if !strings.Contains(err.Error(), "CNAME") {
		t.Errorf("message %q : n'énumère pas les types acceptés", err)
	}
}

func TestEnregistrementAExigeUneIPv4(t *testing.T) {
	cas := []struct {
		donnee string
		valide bool
		motif  string
	}{
		{"192.168.1.10", true, "IPv4 correcte"},
		{"pas-une-ip", false, "texte quelconque"},
		{"192.168.1.999", false, "octet hors bornes"},
		{"", false, "vide"},
		// « ::1 » est une IP VALIDE mais pas une IPv4. net.ParseIP seul
		// l'accepterait, et l'enregistrement A ne résoudrait rien.
		{"::1", false, "IPv6 dans un enregistrement A"},
	}
	for _, c := range cas {
		err := donneeDNSAcceptable("A", "www.exemple.fr", c.donnee)
		if c.valide && err != nil {
			t.Errorf("A %q (%s) refusé : %v", c.donnee, c.motif, err)
		}
		if !c.valide && err == nil {
			t.Errorf("A %q (%s) accepté", c.donnee, c.motif)
		}
	}
}

func TestCibleDeCNAMEEtMXExigeUnFQDN(t *testing.T) {
	for _, typeEnr := range []string{"CNAME", "MX", "NS"} {
		if err := donneeDNSAcceptable(typeEnr, "a.exemple.fr", "cible.exemple.fr"); err != nil {
			t.Errorf("%s vers un FQDN correct refusé : %v", typeEnr, err)
		}
		// « srv » nu : pas de point, donc rien qu'un résolveur puisse suivre.
		if err := donneeDNSAcceptable(typeEnr, "a.exemple.fr", "srv"); err == nil {
			t.Errorf("%s vers « srv » accepté — aucun résolveur ne suivrait ce nom", typeEnr)
		}
		if err := donneeDNSAcceptable(typeEnr, "a.exemple.fr", "192.168.1.1"); err == nil {
			t.Errorf("%s vers une IP accepté — ces types portent un NOM", typeEnr)
		}
	}
}

// TestCNAMECirculaireRefuse : un CNAME qui pointe sur lui-même fait boucler le
// résolveur jusqu'à épuisement. Le refus coûte une comparaison ; le diagnostic,
// sans lui, coûte une après-midi.
func TestCNAMECirculaireRefuse(t *testing.T) {
	err := donneeDNSAcceptable("CNAME", "www.exemple.fr", "www.exemple.fr")
	if err == nil {
		t.Fatal("CNAME circulaire accepté")
	}
	if !strings.Contains(err.Error(), "circulaire") {
		t.Errorf("message %q : ne dit pas ce qui cloche", err)
	}
	// La comparaison ignore le point final et la casse : « WWW.exemple.fr. »
	// désigne le même nom.
	if err := donneeDNSAcceptable("CNAME", "www.exemple.fr", "WWW.exemple.fr."); err == nil {
		t.Error("CNAME circulaire non détecté à la casse ou au point final près")
	}
}

// TestTXTAccepteDuTexteLibre : un TXT porte du SPF, du DKIM, une vérification
// de propriété. Le contraindre interdirait des usages légitimes qu'on n'a pas
// prévus — mais le vide n'a aucun sens.
func TestTXTAccepteDuTexteLibre(t *testing.T) {
	if err := donneeDNSAcceptable("TXT", "@.exemple.fr", "v=spf1 include:_spf.exemple.fr ~all"); err != nil {
		t.Errorf("TXT SPF refusé : %v", err)
	}
	if err := donneeDNSAcceptable("TXT", "@.exemple.fr", "  "); err == nil {
		t.Error("TXT vide accepté")
	}
}

// TestLActionAppelleLaValidation.
//
// # Pourquoi ce test s'ajoute aux précédents
//
// Les tests ci-dessus éprouvent `donneeDNSAcceptable`. Ils passeraient tous sur
// un code où l'action ne l'appellerait PAS — c'est exactement ce qui vient de
// se produire : la fonction existait, correcte, dans command_dns, et plus
// personne ne l'appelait.
//
// Une validation parfaite que personne n'invoque laisse passer autant qu'une
// validation absente. Ce test vérifie le branchement.
//
// Il ne touche pas la base : la validation a lieu AVANT l'écriture, donc une
// donnée invalide provoque un refus sans qu'aucune requête ne parte.
func TestLActionAppelleLaValidation(t *testing.T) {
	_, err := ajouterEnregistrementDNS(Appelant{Username: "root"}, Params{
		"zone":        "exemple.fr",
		"name":        "www",
		"record_type": "A",
		"data":        "pas-une-ip",
	})
	if err == nil {
		t.Fatal("l'action a accepté une IP invalide : la validation n'est pas branchée")
	}
	if !strings.Contains(err.Error(), "invalide") {
		t.Errorf("message %q : ne signale pas une donnée invalide", err)
	}

	// Et sur un type inconnu, pour couvrir l'autre branche.
	_, err = ajouterEnregistrementDNS(Appelant{Username: "root"}, Params{
		"zone":        "exemple.fr",
		"name":        "www",
		"record_type": "AAAA",
		"data":        "::1",
	})
	if err == nil {
		t.Fatal("l'action a accepté un type non pris en charge")
	}
}

// TestTypesAcceptesEstLaSourceUnique.
//
// L'interface web bâtit sa liste déroulante sur TypesDNSAcceptes. Si la
// validation employait une seconde liste, le formulaire proposerait un type que
// l'action refuse — ou omettrait un type qu'elle accepte.
func TestTypesAcceptesEstLaSourceUnique(t *testing.T) {
	if len(TypesDNSAcceptes) == 0 {
		t.Fatal("la liste des types acceptés est vide : aucun enregistrement ne passerait")
	}
	for _, typeEnr := range TypesDNSAcceptes {
		// Une donnée valable pour ce type, pour vérifier que la liste et la
		// validation s'accordent.
		donnee := "cible.exemple.fr"
		switch typeEnr {
		case "A":
			donnee = "10.0.0.1"
		case "TXT":
			donnee = "texte"
		}
		if err := donneeDNSAcceptable(typeEnr, "a.exemple.fr", donnee); err != nil {
			t.Errorf("le type %q figure dans TypesDNSAcceptes mais la validation le "+
				"refuse : %v", typeEnr, err)
		}
	}
}
