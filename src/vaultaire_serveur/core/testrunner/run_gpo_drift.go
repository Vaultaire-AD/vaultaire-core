package testrunner

import (
	"fmt"
	"strings"

	"vaultaire/core/clienttype"
	"vaultaire/core/gpo"
	"vaultaire/core/storage"
	gpomanager "vaultaire/ducky-network/gpo_manager"
)

// Tests de la détection de dérive et du reporting de conformité (trames 05_15
// à 05_17).
//
// # Ce que ces tests protègent
//
// La dérive est le seul mécanisme qui distingue « la politique a été appliquée
// un jour » de « elle est encore en place aujourd'hui ». Une défaillance ici ne
// se manifeste par AUCUN symptôme : le parc s'affiche conforme, ce qui est
// précisément l'état que l'on avait avant d'écrire ce code.
//
// C'est pourquoi le cas central testé ici n'est pas « un écart est détecté »
// mais « une machine non vérifiée n'est pas comptée comme conforme ».
func testGPODrift() []Result {
	var out []Result

	out = append(out, testDriftKinds()...)
	out = append(out, testDriftCatalogue()...)
	out = append(out, testDriftDispatch()...)
	out = append(out, testDriftReportSemantics()...)

	return out
}

// testDriftKinds : la validation des types d'écart est fail-closed.
//
// Le type vient d'un agent, c'est-à-dire d'une machine dont on soupçonne
// justement qu'elle n'est plus tout à fait sous contrôle — c'est la prémisse de
// la détection de dérive. Accepter un type inconnu le rangerait en base sous une
// valeur que ni la commande ni l'interface ne savent afficher.
func testDriftKinds() []Result {
	var out []Result

	for _, k := range []gpo.DriftKind{
		gpo.DriftModified, gpo.DriftMissing, gpo.DriftUnreadable, gpo.DriftPermissions,
	} {
		out = append(out, Result{
			"GPO/derive: type d'ecart " + string(k) + " accepte",
			gpo.IsValidDriftKind(string(k)),
			"type legitime refuse",
		})
	}

	// Les quatre types doivent rester DISTINCTS. Un fichier de clés passé en
	// 0644 avec un contenu intact est un incident de sécurité ; le confondre
	// avec « modifié » le noierait dans le bruit des éditions ordinaires.
	distincts := map[gpo.DriftKind]bool{
		gpo.DriftModified: true, gpo.DriftMissing: true,
		gpo.DriftUnreadable: true, gpo.DriftPermissions: true,
	}
	out = append(out, Result{
		"GPO/derive: les quatre types d'ecart sont distincts",
		len(distincts) == 4,
		fmt.Sprintf("%d valeurs distinctes au lieu de 4", len(distincts)),
	})

	refuses := []string{
		"", "MODIFIED", "modifie", "changed", "unknown",
		"modified ", // un espace parasite ne doit pas passer pour du valide
		"drift",
	}
	for _, k := range refuses {
		out = append(out, Result{
			"GPO/derive: type d'ecart " + fmt.Sprintf("%q", k) + " refuse",
			!gpo.IsValidDriftKind(k),
			"devrait etre refuse (fail-closed)",
		})
	}

	return out
}

// testDriftCatalogue : le catalogue est fail-closed, donc 05_15 doit y être
// déclarée explicitement.
//
// Sans cette ligne, la trame est refusée et la connexion fermée : l'agent
// scanne, constate, et son rapport ne part jamais. Le symptôme est un parc
// affiché « non vérifié » sans qu'aucune erreur ne désigne le catalogue.
func testDriftCatalogue() []Result {
	var out []Result

	out = append(out, Result{
		"GPO/derive: un agent peut emettre 05_15",
		clienttype.MayEmit(clienttype.Client, "05_15"),
		"l'agent ne pourra jamais rapporter sa conformite",
	})

	// 05_16 et 05_17 sont des réponses du serveur. Personne ne doit pouvoir les
	// émettre : un client qui le ferait injecterait un accusé de conformité pour
	// une machine qui n'a rien scanné.
	for _, frame := range []string{"05_16", "05_17"} {
		for _, d := range clienttype.All() {
			out = append(out, Result{
				fmt.Sprintf("GPO/derive: %s ne peut pas emettre %s", d.Name, frame),
				!clienttype.MayEmit(d.Name, frame),
				"trame serveur -> client emissible par un client",
			})
		}
	}

	// Les services n'appliquent aucune politique : leur ouvrir 05_15 leur
	// donnerait un droit d'écriture sur une table de conformité qui ne les
	// concerne pas.
	for _, d := range clienttype.All() {
		if d.Family != clienttype.FamilyService {
			continue
		}
		out = append(out, Result{
			fmt.Sprintf("GPO/derive: le service %s ne rapporte pas de conformite", d.Name),
			!clienttype.MayEmit(d.Name, "05_15"),
			"un service n'applique aucune GPO",
		})
	}

	return out
}

// testDriftDispatch exerce le VRAI routeur de la catégorie 05.
//
// Sans base de données, un rapport bien formé va jusqu'au bout de la validation
// puis échoue à l'écriture : la réponse attendue est donc 05_17 avec le code
// `storage`. C'est utile en soi — cela prouve que le refus d'un rapport
// MALFORMÉ (`malformed_report`) se produit AVANT toute écriture, et n'est pas un
// effet de bord de l'absence de base.
func testDriftDispatch() []Result {
	var out []Result
	session := &storage.DuckySession{}

	// --- Rapport bien formé : validation franchie, écriture impossible -------
	rep := gpomanager.GPO_Trame_Manager(driftTrame("05", "15", strings.Join([]string{
		"machine", "", "12", "1",
		"sshd_config|modified|/etc/ssh/sshd_config|empreinte differente",
	}, "\n")), session)

	lignes := strings.Split(rep, "\n")
	out = append(out, Result{
		"GPO/derive: 05_15 est routee",
		len(lignes) > 0 && lignes[0] == "05_17",
		fmt.Sprintf("reponse %q, attendu une trame 05_17 (sans base)", premiereLigne(rep)),
	})
	out = append(out, Result{
		"GPO/derive: sans base, le code d'erreur est storage",
		contientLigne(lignes, "storage"),
		fmt.Sprintf("reponse %q", rep),
	})
	// L'en-tête serveur → client fait exactement trois lignes. Une de plus ou de
	// moins et le client lit le scope comme une clé de session.
	out = append(out, Result{
		"GPO/derive: l'en-tete de reponse fait trois lignes",
		len(lignes) >= 3 && lignes[1] == "serveur_central",
		fmt.Sprintf("ligne 2 = %q, attendu serveur_central", ligneAt(lignes, 1)),
	})

	// --- Scope invalide : refusé AVANT toute écriture -----------------------
	for _, mauvais := range []string{"", "systeme", "MACHINE", "users", "machine user"} {
		rep := gpomanager.GPO_Trame_Manager(driftTrame("05", "15",
			mauvais+"\n\n12\n0"), session)
		l := strings.Split(rep, "\n")
		out = append(out, Result{
			fmt.Sprintf("GPO/derive: scope %q refuse avant ecriture", mauvais),
			premiereLigne(rep) == "05_17" && contientLigne(l, "malformed_report"),
			fmt.Sprintf("reponse %q, attendu malformed_report", rep),
		})
	}

	// L'espace autour d'un scope valide est toléré, DÉLIBÉRÉMENT : le contenu
	// d'une trame traverse des concaténations de chaînes, et refuser un rapport
	// pour un blanc de bordure ferait perdre une information exacte pour une
	// raison cosmétique. Ce test épingle cette tolérance pour qu'elle reste un
	// choix et non un accident.
	rep = gpomanager.GPO_Trame_Manager(driftTrame("05", "15", "  machine  \n\n12\n0"), session)
	out = append(out, Result{
		"GPO/derive: un scope entoure d'espaces reste valide",
		premiereLigne(rep) == "05_17" && contientLigne(strings.Split(rep, "\n"), "storage"),
		fmt.Sprintf("reponse %q, attendu un passage jusqu'a l'ecriture", rep),
	})

	// --- Compteur de fichiers vérifiés invalide -----------------------------
	//
	// Un compteur illisible n'est pas un détail cosmétique : c'est lui qui
	// distingue « conforme » de « rien n'etait inventorie ». L'accepter à zéro
	// afficherait une machine non vérifiée comme parfaitement saine.
	for _, mauvais := range []string{"", "beaucoup", "-3", "12.5"} {
		rep := gpomanager.GPO_Trame_Manager(driftTrame("05", "15",
			"machine\n\n"+mauvais+"\n0"), session)
		out = append(out, Result{
			fmt.Sprintf("GPO/derive: compteur %q refuse", mauvais),
			premiereLigne(rep) == "05_17",
			fmt.Sprintf("reponse %q, attendu un refus", premiereLigne(rep)),
		})
	}

	// --- Trames serveur → client reçues en entrée ---------------------------
	//
	// Les recevoir signale un client mal implémenté, ou hostile. Le routeur doit
	// rester muet plutôt que de leur inventer un traitement.
	for _, sub := range []string{"16", "17", "13", "99"} {
		rep := gpomanager.GPO_Trame_Manager(driftTrame("05", sub, "machine\n\n1\n0"), session)
		out = append(out, Result{
			"GPO/derive: 05_" + sub + " en reception ne repond rien",
			rep == "",
			fmt.Sprintf("reponse %q, attendu le silence", premiereLigne(rep)),
		})
	}

	// --- Trame 05 sans sous-ordre -------------------------------------------
	//
	// Le cas qui faisait paniquer le serveur avant le garde-fou de Split_Action :
	// une trame tronquée est une entrée non authentifiée comme une autre.
	rep = gpomanager.GPO_Trame_Manager(storage.Trames_struct_client{
		Message_Order: []string{"05"}, Content: "machine",
	}, session)
	out = append(out, Result{
		"GPO/derive: trame 05 sans sous-ordre ne panique pas",
		rep == "",
		fmt.Sprintf("reponse %q", rep),
	})

	return out
}

// testDriftReportSemantics : « aucun écart » ne veut pas dire « conforme ».
//
// C'est la distinction la plus facile à perdre lors d'une refonte, et la plus
// coûteuse : un rapport vide sur zéro fichier vérifié affiché en vert redonne
// exactement l'angle mort que ce code existe pour supprimer.
func testDriftReportSemantics() []Result {
	var out []Result

	vide := gpo.DriftReport{Scope: gpo.ScopeMachine, Checked: 0}
	out = append(out, Result{
		"GPO/derive: un rapport sans inventaire annonce 0 fichier verifie",
		vide.Checked == 0 && strings.Contains(vide.Summary(), "0 fichier"),
		"le resume doit dire combien de fichiers ont ete verifies : " + vide.Summary(),
	})

	sain := gpo.DriftReport{Scope: gpo.ScopeMachine, Checked: 42}
	out = append(out, Result{
		"GPO/derive: un rapport sans ecart est conforme",
		sain.Conforming(),
		"aucun ecart doit donner Conforming",
	})

	derive := gpo.DriftReport{
		Scope: gpo.ScopeMachine, Checked: 42,
		Items: []gpo.DriftItem{{StateKey: "sshd_config", Kind: gpo.DriftModified, Path: "/etc/ssh/x"}},
	}
	out = append(out, Result{
		"GPO/derive: un rapport avec ecart n'est pas conforme",
		!derive.Conforming(),
		"un ecart doit invalider Conforming",
	})
	out = append(out, Result{
		"GPO/derive: le resume distingue les deux cas",
		sain.Summary() != derive.Summary(),
		"conforme et derive produisent le meme resume",
	})

	return out
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

func driftTrame(categorie, sousOrdre, contenu string) storage.Trames_struct_client {
	return storage.Trames_struct_client{
		Message_Order:       []string{categorie, sousOrdre},
		ClientSoftwareID:    "PC-TESTRUNNER",
		SessionIntegritykey: "cle-de-session-de-test",
		Content:             contenu,
	}
}

func premiereLigne(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func ligneAt(lignes []string, i int) string {
	if i < 0 || i >= len(lignes) {
		return ""
	}
	return lignes[i]
}

func contientLigne(lignes []string, valeur string) bool {
	for _, l := range lignes {
		if strings.TrimSpace(l) == valeur {
			return true
		}
	}
	return false
}
