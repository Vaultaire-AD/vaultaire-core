package controle

import (
	"regexp"
	"strings"
	"testing"
)

// La politique SELinux du domaine de l'agent (TO-DO 22). Elle ne se compile
// que contre la politique de référence d'une distribution (install.sh) : ces
// contrôles lisent le texte, pour garder ce qui ne doit pas se perdre.

const (
	politiqueTE = "../../../deployments/selinux/vaultaire.te"
	politiqueFC = "../../../deployments/selinux/vaultaire.fc"
)

// horsTunable retire les blocs tunable_policy(...) et les commentaires : ce qui
// reste est accordé sans condition.
func horsTunable(te string) string {
	var garde []string
	profondeur := 0
	for _, ligne := range strings.Split(te, "\n") {
		nette := strings.TrimSpace(ligne)
		if strings.HasPrefix(nette, "#") {
			continue
		}
		if strings.HasPrefix(nette, "tunable_policy(") {
			profondeur = 1
			continue
		}
		if profondeur > 0 {
			if nette == "')" {
				profondeur = 0
			}
			continue
		}
		garde = append(garde, ligne)
	}
	return strings.Join(garde, "\n")
}

func TestLaResolutionNSSNeJointQueLeDomaineDeLAgent(t *testing.T) {
	te := lire(t, politiqueTE)
	sans := horsTunable(te)
	for _, domaine := range []string{"nsswitch_domain", "sshd_t", "local_login_t"} {
		if !regexp.MustCompile(`(?m)^allow ` + domaine + ` vaultaire_t:unix_stream_socket connectto;`).MatchString(sans) {
			t.Errorf("%s ne peut plus joindre l'agent (vaultaire_t)", domaine)
		}
		if strings.Contains(sans, "allow "+domaine+" unconfined_service_t:unix_stream_socket connectto") {
			t.Errorf("%s joint de nouveau unconfined_service_t sans condition : tout service non confiné, "+
				"pas seulement l'agent. Ce repli doit rester derrière le booléen vaultaire_agent_non_confine", domaine)
		}
	}
	if !strings.Contains(te, "gen_tunable(vaultaire_agent_non_confine, false)") {
		t.Error("le booléen de repli vaultaire_agent_non_confine a disparu, ou est actif par défaut")
	}
}

func TestLAgentEntreDansSonDomaine(t *testing.T) {
	te := lire(t, politiqueTE)
	fc := lire(t, politiqueFC)
	if !strings.Contains(te, "init_daemon_domain(vaultaire_t, vaultaire_exec_t)") {
		t.Error("vaultaire.te ne fait plus entrer l'agent dans vaultaire_t")
	}
	if !regexp.MustCompile(`(?m)^/usr/bin/vaultaire_client\s+--\s+gen_context\(system_u:object_r:vaultaire_exec_t,s0\)`).MatchString(fc) {
		t.Error("vaultaire.fc n'étiquette plus le binaire en vaultaire_exec_t")
	}
	// La clé privée n'est lisible que par l'agent.
	if !regexp.MustCompile(`(?m)^/etc/vaultaire_client\(/\.\*\)\?\s+gen_context\(system_u:object_r:vaultaire_secret_t,s0\)`).MatchString(fc) {
		t.Error("/etc/vaultaire_client n'est plus étiqueté vaultaire_secret_t")
	}
	for _, ligne := range strings.Split(horsTunable(te), "\n") {
		if strings.Contains(ligne, "vaultaire_secret_t") && strings.HasPrefix(strings.TrimSpace(ligne), "allow ") &&
			!strings.HasPrefix(strings.TrimSpace(ligne), "allow vaultaire_t ") {
			t.Errorf("un autre domaine que l'agent accède à la clé privée : %s", strings.TrimSpace(ligne))
		}
	}
	// Refus volontaire : un agent confiné ne désactive pas SELinux.
	if strings.Contains(horsTunable(te), "selinux_config_t") || strings.Contains(te, "seutil_manage_config") {
		t.Error("vaultaire_t reçoit l'écriture de /etc/selinux/config")
	}
}
