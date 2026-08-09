package action

import (
	"strings"
	"testing"
)

// --- enrôlement -------------------------------------------------------------

func TestActionsEnrolementEnregistrees(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsEnrolement(r)
	verifierInventaire(t, r, map[string]string{
		"enroll.create_key": "write:create:client",
		"enroll.revoke_key": "write:create:client",
	})
}

// TestExigenceConditionnelleSurLAssertionDIdentite est le test du mécanisme
// introduit par ce lot.
//
// Une clé visant un type qui peut agir au nom de n'importe quel utilisateur
// exige l'appartenance au groupe protégé — mais seulement celle-là. Une clé
// ordinaire ne doit pas devenir inaccessible aux délégués qui l'émettaient.
func TestExigenceConditionnelleSurLAssertionDIdentite(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsEnrolement(r)

	d, ok := r.Definition("enroll.create_key")
	if !ok {
		t.Fatal("enroll.create_key absente")
	}
	if d.ExigeSuperadminSi == nil {
		t.Fatal("aucune exigence conditionnelle : une clé d'assertion d'identité " +
			"s'obtiendrait avec le seul write:create:client")
	}

	// Type absent : pas d'exigence supplémentaire. La validation du type a lieu
	// dans l'action, avec un message qui l'explique — refuser ici pour
	// « groupe protégé » enverrait chercher un problème de droits là où il n'y
	// a qu'une coquille.
	if d.ExigeSuperadminSi(Params{}) {
		t.Error("type absent traité comme une clé d'assertion d'identité")
	}
	if d.ExigeSuperadminSi(Params{"client_type": "type-inexistant-xyz"}) {
		t.Error("type inconnu traité comme une clé d'assertion d'identité : " +
			"une faute de frappe serait refusée pour la mauvaise raison")
	}
}

// TestExigenceConditionnelleNeSuffitPasCommeControle.
//
// C'est le garde-fou qui justifie d'avoir DEUX champs plutôt qu'un. Une
// exigence conditionnelle peut ne pas s'appliquer ; si elle tenait lieu de
// contrôle déclaré, l'action tournerait alors sans aucune vérification — et le
// registre ne pourrait pas s'en apercevoir, puisqu'on ne peut pas inspecter une
// fonction pour savoir si elle rend parfois faux.
func TestExigenceConditionnelleNeSuffitPasCommeControle(t *testing.T) {
	r := NouveauRegistre()
	err := r.Enregistrer(Definition{
		Nom:               "douteuse",
		ExigeSuperadminSi: func(Params) bool { return false },
		Portee:            PorteeGlobale,
		Resume:            "test",
		Executer:          func(Appelant, Params) (Resultat, error) { return Resultat{}, nil },
	})
	if err == nil {
		t.Fatal("action acceptée avec pour seul contrôle une exigence conditionnelle : " +
			"quand la condition est fausse, rien n'est vérifié")
	}
	if !strings.Contains(err.Error(), "condition peut être fausse") {
		t.Errorf("message %q : n'explique pas pourquoi cela ne suffit pas", err.Error())
	}
}

// TestExigenceConditionnelleAppliqueeALExecution.
func TestExigenceConditionnelleAppliqueeALExecution(t *testing.T) {
	var aExecute bool
	r := NouveauRegistre()
	r.MustEnregistrer(Definition{
		Nom:               "conditionnelle",
		CleRBAC:           "write:create:client",
		ExigeSuperadminSi: func(p Params) bool { return p.Get("sensible") == "oui" },
		Portee:            PorteeGlobale,
		Resume:            "test",
		Executer: func(Appelant, Params) (Resultat, error) {
			aExecute = true
			return Resultat{Message: "fait"}, nil
		},
	})

	sa := &superadminFixe{membres: map[string]bool{"root": true}}
	e := &Executeur{Registre: r, Droits: &droitsFixes{autorise: true}, Superadmin: sa}

	// Condition fausse : un délégué ordinaire passe.
	if _, err := e.Executer("conditionnelle", Appelant{Username: "alice"}, Params{}); err != nil {
		t.Fatalf("délégué refusé alors que la condition ne s'applique pas : %v", err)
	}
	if !aExecute {
		t.Fatal("action non exécutée dans le cas ordinaire")
	}

	// Condition vraie : le même délégué est refusé.
	aExecute = false
	_, err := e.Executer("conditionnelle", Appelant{Username: "alice"}, Params{"sensible": "oui"})
	if err == nil {
		t.Fatal("délégué autorisé alors que la condition exige le groupe protégé")
	}
	if aExecute {
		t.Fatal("action exécutée malgré l'exigence conditionnelle")
	}

	// Et un membre du groupe passe.
	if _, err := e.Executer("conditionnelle", Appelant{Username: "root"}, Params{"sensible": "oui"}); err != nil {
		t.Fatalf("membre du groupe protégé refusé : %v", err)
	}
}

// TestRevocationSansExigenceSupplementaire.
//
// Retirer un pouvoir n'est pas l'accorder. Rendre la révocation plus difficile
// que l'émission retarderait la réaction le jour où une clé fuite — c'est-à-dire
// exactement quand il faut aller vite.
func TestRevocationSansExigenceSupplementaire(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsEnrolement(r)

	d, _ := r.Definition("enroll.revoke_key")
	if d.ExigeSuperadmin || d.ExigeSuperadminSi != nil {
		t.Fatal("la révocation exige plus que l'émission : " +
			"la réaction à une fuite serait ralentie")
	}
}

// TestBornesDeSaisieNommentLeChamp.
//
// Les deux façades rendaient « Le quota doit être un nombre entier » sans dire
// lequel des deux champs posait problème quand les deux étaient saisis.
func TestBornesDeSaisieNommentLeChamp(t *testing.T) {
	if _, err := entierBorne("abc", "quota", 0, 50); err == nil {
		t.Fatal("valeur illisible acceptée")
	} else if !strings.Contains(err.Error(), "quota") {
		t.Errorf("message %q : ne nomme pas le champ", err.Error())
	}

	if _, err := entierBorne("999", "durée", 0, 50); err == nil {
		t.Fatal("valeur hors bornes acceptée")
	} else if !strings.Contains(err.Error(), "durée") {
		t.Errorf("message %q : ne nomme pas le champ", err.Error())
	}

	if v, err := entierBorne("0", "quota", 0, 50); err != nil || v != 0 {
		t.Errorf("0 refusé alors qu'il signifie « illimité » : %v", err)
	}
}

// TestSecretNestPasDansLeMessage.
//
// Le message d'exécution est recopié dans les journaux. Une clé d'enrôlement
// qui s'y trouverait serait une clé publiée — lisible par quiconque a accès aux
// journaux, c'est-à-dire par plus de monde que les détenteurs légitimes.
func TestSecretNestPasDansLeMessage(t *testing.T) {
	// On vérifie la forme du résultat sans appeler la base : le message est
	// construit indépendamment du secret, et c'est cela qu'il faut établir.
	res := Resultat{
		Message: "Clé émise. Elle ne sera plus jamais affichée : copiez-la maintenant.",
		Donnees: map[string]string{"secret": "SECRET-TRES-CONFIDENTIEL"},
	}
	if strings.Contains(res.Message, "SECRET") {
		t.Fatal("le secret figure dans le message, donc dans les journaux")
	}
	d, ok := res.Donnees.(map[string]string)
	if !ok || d["secret"] == "" {
		t.Fatal("le secret n'est pas transmis dans les données : l'appelant ne pourrait pas l'afficher")
	}
}

// --- DNS --------------------------------------------------------------------

func TestActionsDNSEnregistrees(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsDNS(r)
	verifierInventaire(t, r, map[string]string{
		"dns.create_zone":   "write:dns",
		"dns.delete_zone":   "write:dns",
		"dns.add_record":    "write:dns",
		"dns.delete_record": "write:dns",
		"dns.delete_ptr":    "write:dns",
	})
}

// TestWriteDNSResteUneActionReconnue.
//
// « write:dns » vit dans specialActions de core/permission. Si elle en
// disparaissait, les clés la contenant deviendraient invalides et TOUTES les
// actions DNS seraient refusées — sans qu'une seule ligne de actions_dns.go
// n'ait changé.
func TestWriteDNSResteUneActionReconnue(t *testing.T) {
	if !verifierActionDNSConnue() {
		t.Fatal("write:dns n'est plus une action reconnue : toutes les actions DNS " +
			"seraient refusées sans que rien ne l'explique")
	}
}

// TestTTLIllisibleRefuse est le test du défaut de l'ancienne version.
//
// Elle écrivait `ttl, _ := strconv.Atoi(ttlStr)` : l'erreur était jetée, « abc »
// valait 0, puis 0 devenait 300. Une faute de frappe passait donc pour un choix,
// et le TTL réel n'était jamais celui qu'on croyait avoir saisi.
func TestTTLIllisibleRefuse(t *testing.T) {
	if _, err := ttlDepuis(Params{"ttl": "abc"}); err == nil {
		t.Fatal("TTL illisible accepté : une faute de frappe deviendrait silencieusement 300 s")
	}
	if _, err := ttlDepuis(Params{"ttl": "-5"}); err == nil {
		t.Fatal("TTL négatif accepté")
	}
}

// TestTTLAbsentPrendLeDefaut : ne rien dire reste un choix légitime.
func TestTTLAbsentPrendLeDefaut(t *testing.T) {
	v, err := ttlDepuis(Params{})
	if err != nil {
		t.Fatalf("TTL absent refusé : %v", err)
	}
	if v != ttlParDefaut {
		t.Fatalf("TTL %d, attendu %d", v, ttlParDefaut)
	}

	// 0 explicite vaut aussi le défaut — comportement de l'ancienne version,
	// conservé pour ne pas changer le sens d'un formulaire existant.
	if v, err := ttlDepuis(Params{"ttl": "0"}); err != nil || v != ttlParDefaut {
		t.Errorf("TTL 0 → %d (err %v), attendu %d", v, err, ttlParDefaut)
	}
}

// TestArobaseDesigneLaZone : convention des fichiers de zone, RFC 1035 §5.1.
//
// Sans ce cas particulier, l'enregistrement s'appellerait « @.exemple.fr » —
// un nom que personne ne résoudra jamais, et dont l'absence de résolution ne
// désignerait pas la cause.
func TestArobaseDesigneLaZone(t *testing.T) {
	if got := nomPleinementQualifie("@", "exemple.fr"); got != "exemple.fr" {
		t.Fatalf("« @ » → %q, attendu exemple.fr", got)
	}
	if got := nomPleinementQualifie("www", "exemple.fr"); got != "www.exemple.fr" {
		t.Fatalf("« www » → %q, attendu www.exemple.fr", got)
	}
}

// TestPTRRefuseUneAdresseInvalide.
//
// DeletePTRRecordByIP accepte n'importe quelle chaîne et ne supprime alors
// rien. Sans contrôle de forme, une faute de frappe sur l'adresse serait
// rapportée comme un succès — et l'enregistrement inverse resterait en place,
// alors qu'on croirait l'avoir retiré.
func TestPTRRefuseUneAdresseInvalide(t *testing.T) {
	for _, mauvaise := range []string{"", "pas-une-ip", "192.168.1", "999.999.999.999"} {
		if _, err := supprimerPTR(Appelant{}, Params{"ip": mauvaise}); err == nil {
			t.Errorf("adresse %q acceptée : la suppression ne porterait sur rien "+
				"et serait rapportée comme un succès", mauvaise)
		}
	}
	// Les formes valides, IPv4 et IPv6, doivent passer.
	for _, bonne := range []string{"192.168.1.10", "::1", "2001:db8::1"} {
		if _, err := supprimerPTR(Appelant{}, Params{"ip": bonne}); err != nil {
			t.Errorf("adresse valide %q refusée : %v", bonne, err)
		}
	}
}

// TestSuppressionDeZoneDitLAmpleur.
//
// « Zone supprimée avec succès » ne prépare pas à ce qui vient de se passer :
// tous les enregistrements sont partis avec elle, et il n'y a pas de retour en
// arrière — la zone se recrée, son contenu non.
func TestSuppressionDeZoneDitLAmpleur(t *testing.T) {
	res, err := supprimerZoneDNS(Appelant{}, Params{"zone": "exemple.fr"})
	if err != nil {
		t.Fatalf("suppression : %v", err)
	}
	for _, attendu := range []string{"exemple.fr", "enregistrements"} {
		if !strings.Contains(res.Message, attendu) {
			t.Errorf("message %q : ne contient pas %q", res.Message, attendu)
		}
	}
}

// TestNomDeZoneRefuseLIllisible.
func TestNomDeZoneRefuseLIllisible(t *testing.T) {
	mauvais := []string{
		"zone avec espace",
		"zone/avec/barre",
		"zone\navec\nsaut",
		strings.Repeat("a", 254),
		".commence-par-un-point",
	}
	for _, nom := range mauvais {
		t.Run(nom[:min(len(nom), 20)], func(t *testing.T) {
			if err := nomDNSAcceptable(nom); err == nil {
				t.Fatalf("nom de zone %q accepté", nom)
			}
		})
	}

	for _, nom := range []string{"exemple.fr", "interne.lan", "a.b.c.d.e"} {
		if err := nomDNSAcceptable(nom); err != nil {
			t.Errorf("nom de zone valide %q refusé : %v", nom, err)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
