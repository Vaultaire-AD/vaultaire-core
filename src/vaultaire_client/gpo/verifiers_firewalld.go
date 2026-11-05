package gpo

import (
	"fmt"
	"strings"
)

// Attente firewalld — recette du 29/10.
//
// La branche nftables déclarait son attente (CheckNftRule) ; la branche
// firewalld, rien. Sur Rocky, un « firewall-cmd --remove-port=8999/tcp » fermait
// le port voulu par la GPO, et le scan déclarait la machine conforme : sans
// attente, il n'y avait rien à constater.
const (
	// CheckFirewalldRegle : Target est « port:<port>/<proto> » ou
	// « rich:<règle> », Expect « present » ou « absent ».
	CheckFirewalldRegle = "firewalld_regle"
)

func init() {
	registerChecker(CheckFirewalldRegle, verifierRegleFirewalld)
}

// cibleFirewalld construit la Target de l'attente pour une règle posée.
func cibleFirewalld(spec, rich string) string {
	if rich != "" {
		return "rich:" + rich
	}
	return "port:" + spec
}

// requeteFirewalld rend les arguments de la question à poser à firewall-cmd.
func requeteFirewalld(target string) ([]string, error) {
	switch {
	case strings.HasPrefix(target, "port:"):
		return []string{"--query-port=" + strings.TrimPrefix(target, "port:")}, nil
	case strings.HasPrefix(target, "rich:"):
		return []string{"--query-rich-rule=" + strings.TrimPrefix(target, "rich:")}, nil
	}
	return nil, fmt.Errorf("attente firewalld illisible : %q", target)
}

// verifierRegleFirewalld interroge la configuration EN VIGUEUR (runtime) puis
// la configuration permanente : la première dit ce qui filtre maintenant, la
// seconde ce qui reviendra au prochain rechargement.
func verifierRegleFirewalld(c SystemCheck) (bool, string, error) {
	if !commandExists("firewall-cmd") {
		return false, "", fmt.Errorf("firewall-cmd absent de cette machine")
	}
	if out, err := runCommand("systemctl", "is-active", "firewalld"); err != nil ||
		strings.TrimSpace(out) != "active" {
		return false, "firewalld n'est plus actif : la regle " + c.Target + " ne filtre plus rien", nil
	}
	question, err := requeteFirewalld(c.Target)
	if err != nil {
		return false, "", err
	}
	voulue := c.Expect == "present"
	for _, couche := range []struct {
		nom  string
		args []string
	}{
		{"en vigueur", question},
		{"permanente", append([]string{"--permanent"}, question...)},
	} {
		// --query-* : sortie « yes » et code 0, ou « no » et code 1.
		out, _ := runCommand("firewall-cmd", couche.args...)
		presente := strings.TrimSpace(out) == "yes"
		if presente != voulue {
			etat := "absente"
			if presente {
				etat = "presente"
			}
			return false, fmt.Sprintf("regle firewalld %s : %s attendue, %s dans la configuration %s",
				c.Target, c.Expect, etat, couche.nom), nil
		}
	}
	return true, "", nil
}
