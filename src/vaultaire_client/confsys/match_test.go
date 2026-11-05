package confsys

import (
	"strings"
	"testing"
)

// TO-DO 208 : un sshd_config qui se termine par un bloc Match.
const matchFinal = "Match User sauvegarde\n    X11Forwarding no\n    AllowTcpForwarding no\n"

func posteAvecMatch(t *testing.T, famille string) poste {
	t.Helper()
	p := nouveauPoste(t, famille, false)
	p.origine["etc/ssh/sshd_config"] += matchFinal
	p.ecrire("etc/ssh/sshd_config", p.origine["etc/ssh/sshd_config"])
	return p
}

// Le script et l'agent posent le bloc AVANT le Match, octet pour octet.
func TestLeBlocVaAvantLeMatch(t *testing.T) {
	for _, famille := range []string{"rocky", "debian"} {
		t.Run(famille, func(t *testing.T) {
			p := posteAvecMatch(t, famille)
			p.installer()
			c := p.lire("etc/ssh/sshd_config")
			attendu, _ := Regles(famille, false)
			for _, r := range attendu {
				if r.Rel != "etc/ssh/sshd_config" {
					continue
				}
				agent, _ := r.Produire(p.origine[r.Rel])
				if agent != c {
					t.Fatalf("le script et l'agent divergent :\n--- script ---\n%s--- agent ---\n%s", c, agent)
				}
			}
			debut, fin, match := strings.Index(c, "# vaultaire-conf v1 - debut"),
				strings.Index(c, "# vaultaire-conf - fin"), strings.Index(c, "Match User sauvegarde")
			if debut < 0 || fin < debut || match < fin {
				t.Fatalf("bloc %d-%d, Match %d :\n%s", debut, fin, match, c)
			}
			if !strings.HasSuffix(c, matchFinal) {
				t.Errorf("le bloc Match n'est plus intact en fin de fichier :\n%s", c)
			}
			// Et rien ne reste à faire.
			if r := Reconcilier(p.env(&fauxSysteme{})); r.Etat != EtatConforme {
				t.Errorf("%s : %s", r.Etat, r.Motif)
			}
		})
	}
}

// La machine laissée en écart avant le 208 : jamais réécrite, donc sans
// marqueur (v0) — elle est réconciliée au démarrage suivant, sans montée de
// version.
func TestLaMachineEnEcartSeRepare(t *testing.T) {
	p := posteAvecMatch(t, "rocky")
	p.installer()
	p.ecrire("etc/ssh/sshd_config", p.origine["etc/ssh/sshd_config"])
	r := Reconcilier(p.env(&fauxSysteme{}))
	if r.Etat != EtatReconciliee || !strings.Contains(r.Motif, "ssh/sshd_config v0→v1") {
		t.Fatalf("%s : %s", r.Etat, r.Motif)
	}
	c := p.lire("etc/ssh/sshd_config")
	if strings.Index(c, "UsePAM yes") > strings.Index(c, "Match User sauvegarde") {
		t.Errorf("bloc après le Match :\n%s", c)
	}
}

// Plusieurs Match, Match en minuscules ou indenté, et « #Match » commenté.
func TestReecrireSSHDEtLesMatch(t *testing.T) {
	for nom, k := range map[string]struct{ entree, avant string }{
		"deux Match": {"A 1\nMatch User a\n  X 1\nMatch User b\n  X 2\n", "Match User a"},
		"minuscules": {"A 1\nmatch group g\n  X 1\n", "match group g"},
		"indenté":    {"A 1\n   Match Address 10.0.0.0/8\n  X 1\n", "   Match Address"},
		"commenté":   {"A 1\n#Match User anoncvs\n#  X11Forwarding no\n", ""},
		"sans Match": {"A 1\nB 2\n", ""},
		"Matchless":  {"A 1\nMatchless 3\n", ""},
	} {
		c := reecrireSSHD(k.entree)
		bloc := strings.Index(c, blocSSHD)
		if bloc < 0 {
			t.Fatalf("%s : bloc absent", nom)
		}
		if k.avant == "" {
			if !strings.HasSuffix(c, blocSSHD) {
				t.Errorf("%s : bloc pas en fin de fichier :\n%s", nom, c)
			}
			continue
		}
		if i := strings.Index(c, k.avant); i != bloc+len(blocSSHD) {
			t.Errorf("%s : bloc pas juste avant %q :\n%s", nom, k.avant, c)
		}
	}
}
