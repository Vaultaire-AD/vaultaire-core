package miseajour

import (
	"fmt"
	"strings"
)

// Le compte rendu de configuration système d'un agent — 09_07, TO-DO 117.
//
// L'agent tient ses piles PAM, sshd_config et nsswitch.conf à la version que
// son code attend, une fois par démarrage, et dit ce qu'il en est. Le core le
// range (id_logiciels.agent_conf_*) et « vlt agent » le montre : un écart —
// sshd -t qui refuse, une pile personnalisée où l'agent ne sait pas se
// brancher — est à traiter sur la machine.

// Etats : les MÊMES chaînes que vaultaire_client/confsys, figées des deux
// côtés par un test.
const (
	ConfConforme        = "conforme"
	ConfReconciliee     = "reconciliee"
	ConfEcart           = "ecart"
	ConfDesactivee      = "desactivee"
	ConfNonPrisEnCharge = "non_pris_en_charge"
)

// ConfValide dit si un état reçu est connu.
func ConfValide(e string) bool {
	switch e {
	case ConfConforme, ConfReconciliee, ConfEcart, ConfDesactivee, ConfNonPrisEnCharge:
		return true
	}
	return false
}

// CompteRenduConf : une 09_07 lue.
type CompteRenduConf struct {
	Etat  string
	Motif string
}

// LireCompteRenduConf lit le contenu d'une 09_07 : « <état> · <motif> ».
func LireCompteRenduConf(contenu string) (CompteRenduConf, error) {
	l := strings.SplitN(strings.ReplaceAll(contenu, "\r", ""), "\n", 2)
	c := CompteRenduConf{Etat: strings.TrimSpace(l[0])}
	if len(l) > 1 {
		c.Motif = strings.TrimSpace(strings.ReplaceAll(l[1], "\n", " "))
	}
	if !ConfValide(c.Etat) {
		return CompteRenduConf{}, fmt.Errorf("09_07 : état inconnu %q", c.Etat)
	}
	return c, nil
}
