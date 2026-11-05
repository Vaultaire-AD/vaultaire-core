package gpo

import (
	"fmt"
	"sort"
	"strings"

	logs "duckynetworkclient/V1/duckynetwork/logs"
)

// La configuration SSH EN VIGUEUR — TO-DO 182.
//
// # Le défaut
//
// Le module `ssh_server_config` écrit un fragment dans `sshd_config.d`, et seul
// le hachage de ce fragment était surveillé. Or sshd retient la PREMIÈRE valeur
// qu'il lit pour une directive : une ligne écrite plus haut — dans
// `sshd_config` avant la ligne `Include`, ou dans un fragment trié avant celui de
// Vaultaire — gagne, et le fragment, intact, n'a plus d'effet. Recette du
// 12/10 (§ 7d), reproduite le 28/10 : `MaxAuthTries 10` en tête de
// `sshd_config`, sshd applique 10, la GPO demande 3, et la machine était
// déclarée « conforme ».
//
// # Ce qui est constaté
//
// `sshd -T` : la configuration que sshd appliquerait à une connexion sans
// `Match` particulier, toutes inclusions résolues. C'est la seule source qui
// réponde à la question posée — que fait sshd ? — sans réimplémenter son ordre
// de lecture.
//
// Seules les directives que la politique fixe sont comparées : le reste de la
// configuration appartient à la machine.

// CheckSSHEffectif : Target « sshd », Expect « directive=valeur,… » en
// minuscules, sous les noms que rend `sshd -T`.
const (
	CheckSSHEffectif = "sshd_effectif"
	// CheckSSHClientEffectif : la configuration du CLIENT ssh, constatée par
	// `ssh -G` (TO-DO 246). Target « ssh ».
	CheckSSHClientEffectif = "ssh_client_effectif"
)

func init() {
	registerChecker(CheckSSHEffectif, verifierSSHEffectif)
	registerChecker(CheckSSHClientEffectif, verifierSSHClientEffectif)
}

// equivalentsSSHD : les valeurs que sshd écrit autrement qu'on ne les configure.
// `prohibit-password` s'est longtemps appelé `without-password`, et `sshd -T`
// rend encore l'ancien nom sur plusieurs versions.
var equivalentsSSHD = map[string]string{
	"without-password": "prohibit-password",
	// `ssh -G` rend StrictHostKeyChecking en true/false ; la politique écrit
	// yes/no (TO-DO 246).
	"true":  "yes",
	"false": "no",
}

// normaliserValeurSSH : la forme commune de sshd et ssh.
func normaliserValeurSSH(v string) string { return normaliserValeurSSHD(v) }

func normaliserValeurSSHD(v string) string {
	v = strings.ToLower(strings.Join(strings.Fields(v), " "))
	if e, ok := equivalentsSSHD[v]; ok {
		return e
	}
	return v
}

// attenteSSHD compose l'Expect d'une liste de directives « Mot valeur ».
func attenteSSHD(directives []string) string {
	var parts []string
	for _, d := range directives {
		mot, valeur, ok := strings.Cut(strings.TrimSpace(d), " ")
		if !ok {
			continue
		}
		parts = append(parts, strings.ToLower(mot)+"="+normaliserValeurSSHD(valeur))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// lireSSHDT découpe la sortie de `sshd -T` : une directive par ligne, en
// minuscules, la valeur après le premier espace. Une directive répétée
// (`hostkey`, `listenaddress`) garde sa première valeur : aucune de celles-là
// n'est fixée par la politique.
func lireSSHDT(sortie string) map[string]string {
	out := map[string]string{}
	for _, ligne := range strings.Split(sortie, "\n") {
		mot, valeur, ok := strings.Cut(strings.TrimSpace(ligne), " ")
		if !ok {
			continue
		}
		mot = strings.ToLower(mot)
		if _, deja := out[mot]; !deja {
			out[mot] = normaliserValeurSSHD(valeur)
		}
	}
	return out
}

// ecartsSSHD compare l'attendu à la configuration en vigueur. Une directive
// absente de `sshd -T` est un écart : sshd ne l'applique pas.
func ecartsSSHD(attendu, enVigueur map[string]string) []string {
	mots := make([]string, 0, len(attendu))
	for m := range attendu {
		mots = append(mots, m)
	}
	sort.Strings(mots)
	var ecarts []string
	for _, m := range mots {
		constate, ok := enVigueur[m]
		if !ok {
			constate = "absente"
		}
		if constate != attendu[m] {
			ecarts = append(ecarts, ecartConstate("sshd "+m, attendu[m], constate))
		}
	}
	return ecarts
}

// configurationSSHDEnVigueur lance `sshd -T`.
func configurationSSHDEnVigueur() (map[string]string, error) {
	if !commandExists("sshd") {
		return nil, fmt.Errorf("sshd absent de cette machine")
	}
	sortie, err := runCommand("sshd", "-T")
	if err != nil {
		// Configuration invalide, clé d'hôte illisible : on ne sait pas ce que
		// sshd applique. Incertitude, pas écart — comme pour sysctl.
		return nil, fmt.Errorf("configuration sshd illisible (sshd -T) : %v", err)
	}
	return lireSSHDT(sortie), nil
}

// verifierSSHEffectif constate que sshd applique ce que la politique fixe.
func verifierSSHEffectif(c SystemCheck) (bool, string, error) {
	attendu := champsAttendus(c.Expect)
	if len(attendu) == 0 {
		return true, "", nil
	}
	enVigueur, err := configurationSSHDEnVigueur()
	if err != nil {
		return false, "", err
	}
	if ecarts := ecartsSSHD(attendu, enVigueur); len(ecarts) > 0 {
		return false, strings.Join(ecarts, " ; ") + " — " + motifMasque, nil
	}
	return true, "", nil
}

// motifMasque dit où chercher : c'est toujours une directive lue AVANT le
// fragment de Vaultaire.
const motifMasque = "une directive lue avant " + sshFragmentPath +
	" l'emporte (sshd_config avant sa ligne Include, ou un fragment trie avant)"

// attentesExigees : les attentes qu'un module DOIT avoir inscrites. Un module
// posé par une version antérieure — qui ne les déclarait pas — les inscrit au
// cycle suivant, SANS être rejoué (voir applyModule) : sans cela, une politique
// qui ne change pas ne serait jamais vérifiée par `sshd -T`, et le défaut du
// TO-DO 182 resterait entier sur tout le parc déjà en place.
var attentesExigees = map[string][]string{
	ModuleSSHServerConfig: {CheckSSHEffectif},
}

// declarerAttentes inscrit, sans rien appliquer, les attentes d'un module.
func declarerAttentes(m Module) {
	switch m.Type {
	case ModuleSSHServerConfig:
		if d := directivesSSH(m); len(d) > 0 {
			recordCheck(CheckSSHEffectif, "sshd", attenteSSHD(d))
		}
	}
}

// attenteManquante dit si l'état précédent manque d'une attente exigée pour ce
// module.
func attenteManquante(m Module, previous *ScopeState) bool {
	return previous.manqueAttente(m.Type, m.StateKey)
}

// manqueAttente : le module `cle`, de type `typ`, n'a pas l'une des attentes
// exigées pour son type.
func (s *ScopeState) manqueAttente(typ, cle string) bool {
	exigees := attentesExigees[typ]
	if len(exigees) == 0 || s == nil {
		return false
	}
	for _, kind := range exigees {
		trouvee := false
		for _, c := range s.Checks {
			if c.Kind != kind {
				continue
			}
			for _, p := range c.proprietaires() {
				if p == cle {
					trouvee = true
				}
			}
		}
		if !trouvee {
			return true
		}
	}
	return false
}

// rattraperAttentesMachine oublie l'empreinte de politique de l'état machine
// quand l'un de ses modules manque d'une attente exigée : le core renverra la
// politique, et applyModule inscrira l'attente. Rend le nombre de modules
// concernés.
//
// Le type d'un module se lit dans sa clé d'état (« ssh_server_config:- ») :
// l'état ne garde pas ses paramètres.
func rattraperAttentesMachine() int {
	state := LoadState()
	s := state.Machine
	if s == nil || s.Fingerprint == "" {
		return 0
	}
	n := 0
	for cle := range s.Modules {
		typ, _, _ := strings.Cut(cle, ":")
		if s.manqueAttente(typ, cle) {
			n++
		}
	}
	if n == 0 {
		return 0
	}
	s.Fingerprint = ""
	if err := SaveScopeState(ScopeMachine, "", s); err != nil {
		logs.Write_log("ERROR", "GPO: etat non enregistre avant le rattrapage des attentes : "+err.Error())
		return 0
	}
	logs.Write_log("INFO", fmt.Sprintf(
		"GPO: %d module(s) poses avant la verification de leur effet (TO-DO 182) — "+
			"politique redemandee, attentes inscrites sans reappliquer", n))
	return n
}

// --- le client ssh — TO-DO 246 ----------------------------------------------

// motifMasqueClient : pour le client, ce qui l'emporte est lu avant le
// fragment, dans ssh_config ou dans un fragment trié avant.
const motifMasqueClient = "une directive lue avant " + sshClientDropIn +
	" l'emporte (ssh_config avant sa ligne Include, ou un fragment trie avant)"

// hoteDeVerification : `ssh -G` résout la configuration POUR un hôte, sans se
// connecter. Un nom réservé (RFC 6761) ne peut pas tomber sous un bloc `Host`
// réel, et ne fait aucune requête DNS.
const hoteDeVerification = "vaultaire-verification.invalid"

// configurationSSHClientEnVigueur lance `ssh -G` sur la seule configuration
// SYSTÈME (-F) : celle de root, dans ~/.ssh/config, ne concerne pas le parc.
func configurationSSHClientEnVigueur() (map[string]string, error) {
	if !commandExists("ssh") {
		return nil, fmt.Errorf("client ssh absent de cette machine")
	}
	sortie, err := runCommand("ssh", "-F", "/etc/ssh/ssh_config", "-G", hoteDeVerification)
	if err != nil {
		return nil, fmt.Errorf("configuration ssh illisible (ssh -G) : %v", err)
	}
	return lireSSHDT(sortie), nil
}

// verifierSSHClientEffectif constate que le client ssh applique ce que la
// politique fixe.
func verifierSSHClientEffectif(c SystemCheck) (bool, string, error) {
	attendu := champsAttendus(c.Expect)
	if len(attendu) == 0 {
		return true, "", nil
	}
	enVigueur, err := configurationSSHClientEnVigueur()
	if err != nil {
		return false, "", err
	}
	if ecarts := ecartsSSHD(attendu, enVigueur); len(ecarts) > 0 {
		for i := range ecarts {
			ecarts[i] = strings.Replace(ecarts[i], "sshd ", "ssh ", 1)
		}
		return false, strings.Join(ecarts, " ; ") + " — " + motifMasqueClient, nil
	}
	return true, "", nil
}
