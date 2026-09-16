package gpo

import (
	"strings"
	"testing"
)

// L'ANALYSE des vérificateurs du temps et de l'audit.
//
// Aucune commande n'est lancée : `timedatectl` et `auditctl` répondent
// différemment selon la machine, et souvent pas du tout dans un conteneur. Ce
// qui est éprouvé, c'est ce que le vérificateur FAIT de leur sortie.

// --- serveurs de temps ------------------------------------------------------

// TestLesDeuxFormatsDeListeSontLus.
//
// Les deux bouts n'écrivent pas pareil : la politique sépare par des virgules,
// `normalizeList` en fait des espaces avant écriture, et timedatectl rend des
// espaces. Un vérificateur qui ne lirait qu'un seul séparateur signalerait une
// dérive permanente sur l'autre format.
func TestLesDeuxFormatsDeListeSontLus(t *testing.T) {
	cas := []struct {
		quoi   string
		brut   string
		nombre int
	}{
		{"virgules (politique)", "a.ntp.fr,b.ntp.fr,c.ntp.fr", 3},
		{"espaces (timedatectl)", "a.ntp.fr b.ntp.fr c.ntp.fr", 3},
		{"mélange et espaces superflus", " a.ntp.fr,  b.ntp.fr ,c.ntp.fr ", 3},
		{"un seul", "a.ntp.fr", 1},
		{"vide", "", 0},
		{"séparateurs seuls", " , , ", 0},
		{"saut de ligne final", "a.ntp.fr b.ntp.fr\n", 2},
	}
	for _, c := range cas {
		if n := len(serveursNTP(c.brut)); n != c.nombre {
			t.Errorf("%s : %d serveur(s), attendu %d — %q", c.quoi, n, c.nombre, c.brut)
		}
	}
}

// TestLOrdreDesServeursNeCompteJamais.
//
// LE test de la partie NTP. timesyncd bascule d'un serveur à l'autre selon leur
// disponibilité et peut réordonner ce qu'il rend. Exiger l'ordre exact ferait
// signaler une dérive sur une machine dont la configuration n'a pas bougé d'un
// caractère — et qu'aucune réapplication ne corrigerait.
func TestLOrdreDesServeursNeCompteJamais(t *testing.T) {
	attendus := serveursNTP("a.ntp.fr,b.ntp.fr,c.ntp.fr")
	constates := serveursNTP("c.ntp.fr b.ntp.fr a.ntp.fr")

	if !egalesIgnorantLOrdre(attendus, constates) {
		t.Error("les mêmes serveurs dans un ordre différent sont pris pour une dérive")
	}
}

// TestUnServeurEnTropEstUneDerive.
//
// Le NOMBRE compte, même si tous ceux de la politique sont là : c'est un serveur
// de temps que personne n'a demandé, et il peut servir la mauvaise heure.
func TestUnServeurEnTropEstUneDerive(t *testing.T) {
	attendus := serveursNTP("a.ntp.fr,b.ntp.fr")

	cas := map[string]string{
		"un serveur en trop":    "a.ntp.fr b.ntp.fr pirate.ntp.fr",
		"un serveur en moins":   "a.ntp.fr",
		"un serveur remplacé":   "a.ntp.fr autre.ntp.fr",
		"aucun serveur":         "",
		"tous différents":       "x.ntp.fr y.ntp.fr",
	}
	for quoi, constate := range cas {
		if egalesIgnorantLOrdre(attendus, serveursNTP(constate)) {
			t.Errorf("%s : %q est pris pour conforme", quoi, constate)
		}
	}
}

// --- règles d'audit ---------------------------------------------------------

// auditctlExemple reproduit une sortie réelle d'`auditctl -l`.
//
// Noter la NORMALISATION : la règle écrite « -w /etc/passwd -p wa -k vaultaire »
// ressort avec ses champs dans cet ordre-là, et une règle de syscall porte son
// étiquette sous « key= ». C'est pourquoi la comparaison porte sur l'étiquette
// et jamais sur la ligne entière.
const auditctlExemple = "-w /etc/passwd -p wa -k identites\n" +
	"-w /opt/vaultaire/config -p rwxa -k config\n" +
	"-a always,exit -F arch=b64 -S execve -F key=execution\n" +
	"-w /etc/shadow -p wa -k secrets\n"

func TestUneRegleEstRetrouveeParSonEtiquette(t *testing.T) {
	for _, etiquette := range []string{"identites", "config", "secrets", "execution"} {
		if !regleAuditPresente(auditctlExemple, etiquette) {
			t.Errorf("règle %q non trouvée alors qu'elle est chargée", etiquette)
		}
	}
}

// TestUneEtiquetteNEstPasUneSousChaine.
//
// LE test de la partie audit. Une étiquette « vaultaire » se retrouve dans le
// CHEMIN surveillé « /opt/vaultaire/config » : une recherche de sous-chaîne
// conclurait qu'une règle « vaultaire » est chargée en lisant la règle d'un
// autre — donc déclarerait conforme une machine dont la règle a disparu.
func TestUneEtiquetteNEstPasUneSousChaine(t *testing.T) {
	if regleAuditPresente(auditctlExemple, "vaultaire") {
		t.Error("l'étiquette a été trouvée dans un chemin surveillé, pas dans un « -k »")
	}
	if regleAuditPresente(auditctlExemple, "ident") {
		t.Error("un préfixe d'étiquette a été accepté pour l'étiquette entière")
	}
	if regleAuditPresente(auditctlExemple, "passwd") {
		t.Error("un morceau de chemin a été pris pour une étiquette")
	}
}

// TestUnNoyauSansRegleEstReconnu.
//
// « No rules » est ce que rend auditctl après un `auditctl -D` — la commande
// d'une ligne qui vide tout sans toucher à un seul fichier. C'est le cas le plus
// grave que ce vérificateur existe pour voir.
func TestUnNoyauSansRegleEstReconnu(t *testing.T) {
	for _, sortie := range []string{"No rules", "no rules", "No rules\n", ""} {
		if regleAuditPresente(sortie, "identites") {
			t.Errorf("sortie %q : une règle est déclarée chargée sur un noyau vide", sortie)
		}
	}
}

func TestUneEtiquetteVideNeTrouveRien(t *testing.T) {
	if regleAuditPresente(auditctlExemple, "") {
		t.Error("une étiquette vide a trouvé une règle")
	}
	if regleAuditPresente(auditctlExemple, "   ") {
		t.Error("une étiquette d'espaces a trouvé une règle")
	}
}

// TestLesTroisFormesDEtiquetteSontLues : auditctl n'écrit pas toujours pareil.
func TestLesTroisFormesDEtiquetteSontLues(t *testing.T) {
	cas := map[string]string{
		"-w /etc/passwd -p wa -k identites":              "identites",
		"-w /etc/passwd -p wa -k=identites":              "identites",
		"-a always,exit -F arch=b64 -F key=identites":    "identites",
		"-a always,exit -F arch=b64 -S execve":           "",
		"":                                               "",
	}
	for ligne, attendu := range cas {
		if got := etiquetteDeRegle(ligne); got != attendu {
			t.Errorf("%q → %q, attendu %q", ligne, got, attendu)
		}
	}
}

// --- ce que ce lot refuse d'affirmer ----------------------------------------

// TestAucuneAttenteSurCeQuiDependDUneSession.
//
// `system_env` et `resource_limits` étaient candidats et ne sont pas
// vérifiables : le premier ne s'observe que dans un shell de connexion, qui
// n'est pas celui de l'agent et diffère par utilisateur ; le second dépend de la
// session, l'appliqueur le dit lui-même — « nouvelles sessions ».
//
// Le test lit la source parce que la propriété est une ABSENCE : rien à
// exécuter, seulement à constater qu'aucune attente n'est déclarée. Sans lui,
// quelqu'un croirait à un oubli et comblerait le trou par une observation qui ne
// répond pas à la question posée.
func TestAucuneAttenteSurCeQuiDependDUneSession(t *testing.T) {
	source := lireSource(t, "appliers_system.go") +
		lireSource(t, "appliers_user.go") +
		lireSource(t, "appliers_user_extra.go")

	for _, interdit := range []string{"CheckSystemEnv", "CheckUserEnv", "CheckResourceLimits"} {
		if strings.Contains(source, "recordCheck("+interdit) {
			t.Errorf("une attente %s est déclarée : elle constaterait l'environnement "+
				"de l'agent, pas celui d'une session utilisateur", interdit)
		}
	}
}

// TestAucuneAttenteQuandTimesyncdNAPasRedemarre.
//
// Garde-fou de la décision la plus facile à défaire : quand le redémarrage de
// timesyncd échoue, la machine utilise probablement chrony ou ntpd. Déclarer
// l'attente quand même ferait lire au vérificateur les serveurs d'un autre
// démon — donc une dérive permanente sur une machine dont la configuration est
// pourtant écrite.
func TestAucuneAttenteQuandTimesyncdNAPasRedemarre(t *testing.T) {
	source := lireSource(t, "appliers_system.go")

	iEchec := strings.Index(source, "systemd-timesyncd non redemarre")
	iAttente := strings.Index(source, "recordCheck(CheckNTPServers")
	if iEchec < 0 || iAttente < 0 {
		t.Fatal("applyNTPConfig ne ressemble plus à ce que ce test garde")
	}
	if iAttente < iEchec {
		t.Error("l'attente NTP est déclarée AVANT le retour d'échec du redémarrage : " +
			"elle serait posée sur une machine où rien n'a été chargé")
	}
}
