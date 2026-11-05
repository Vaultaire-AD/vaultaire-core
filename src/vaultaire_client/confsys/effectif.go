package confsys

import (
	"fmt"
	"path/filepath"
	"strings"
)

// La configuration sshd EFFECTIVE — TO-DO 209.
//
// Le marqueur dit ce que l'agent a écrit, pas ce que sshd applique. sshd
// retient la PREMIÈRE valeur lue d'une directive : le bloc de Vaultaire,
// suivi de son Include, l'emporte sur sshd_config.d — mais pas sur ce qui est
// lu AVANT lui. Une ligne « UsePAM no » ou un « Include » remis en tête du
// fichier par un administrateur ou une mise à jour du paquet openssh passe
// devant, et le marqueur, toujours à jour, ne déclenche aucune réécriture.
//
// D'où ce contrôle, après chaque passage et dans --config-status : « sshd -T »
// rend la configuration effective, comparée à ce que le bloc demande. Un
// écart est remonté (état « ecart »), avec la ligne qui l'impose quand on la
// retrouve ; RIEN n'est écrit — les fichiers en cause ne sont pas à Vaultaire,
// et deviner lequel corriger serait pire que le dire.

// NomEffectif : le constat de ce contrôle.
const NomEffectif = "ssh/sshd_config (effectif)"

// ActionEcartEffectif : sshd applique autre chose que ce que le bloc demande.
const ActionEcartEffectif = "écart effectif"

// attenduSSHD : les directives du bloc, clé en minuscules → valeur, dans
// l'ordre du bloc. Lues dans blocSSHD lui-même : une seule source.
//
// Écartées : Include (sshd -T ne l'imprime pas) et
// ChallengeResponseAuthentication (alias de KbdInteractiveAuthentication
// depuis OpenSSH 8.7, que sshd -T n'imprime plus).
func attenduSSHD() ([]string, map[string]string) {
	var cles []string
	m := map[string]string{}
	for _, l := range lignes(blocSSHD) {
		if strings.HasPrefix(l, "#") || strings.TrimSpace(l) == "" {
			continue
		}
		k, v, _ := strings.Cut(l, " ")
		k = strings.ToLower(k)
		if k == "include" || k == "challengeresponseauthentication" {
			continue
		}
		cles = append(cles, k)
		m[k] = strings.TrimSpace(v)
	}
	return cles, m
}

// lireSSHDT : la sortie de « sshd -T », clé → valeur. Une directive à
// valeurs multiples n'apparaît qu'une fois pour celles qu'on contrôle.
func lireSSHDT(sortie string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(sortie, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok {
			continue
		}
		k = strings.ToLower(k)
		if _, deja := m[k]; !deja {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// ControlerSSHDEffectif rend un constat d'écart, ou nil si sshd applique ce
// que le bloc demande.
func ControlerSSHDEffectif(e Env) *Constat {
	conf := e.chemin("etc/ssh/sshd_config")
	if _, existe := lireSiExiste(conf); !existe {
		return nil // déjà dit par la règle de sshd_config
	}
	sortie, err := e.Systeme("sshd", "-T", "-f", conf)
	k := &Constat{Nom: NomEffectif, Groupe: GroupeSSHD, Action: ActionEcartEffectif}
	if err != nil {
		k.Detail = "sshd -T refuse la configuration en place : " + premieresLignes(string(sortie), 2)
		return k
	}
	effectif := lireSSHDT(string(sortie))
	if len(effectif) == 0 {
		k.Detail = "sshd -T n'a rien rendu"
		return k
	}
	cles, attendu := attenduSSHD()
	var ecarts []string
	for _, c := range cles {
		v, present := effectif[c]
		if !present {
			// Une directive que cet OpenSSH ne connaît pas : sshd -t l'aurait
			// refusée dans le bloc — pas un écart à signaler ici.
			continue
		}
		if !strings.EqualFold(v, attendu[c]) {
			ligne := fmt.Sprintf("%s %s (attendu %s)", c, v, attendu[c])
			if o := origine(e.Racine, conf, c); o != "" {
				ligne += " — imposé par " + o
			}
			ecarts = append(ecarts, ligne)
		}
	}
	if len(ecarts) == 0 {
		return nil
	}
	k.Detail = strings.Join(ecarts, " ; ")
	return k
}

// origine cherche la première ligne, lue AVANT le bloc de Vaultaire, qui pose
// cette directive : dans sshd_config lui-même, ou dans un fichier qu'un
// Include y amène avant le bloc. Rend « sshd_config:12 » ou
// « /etc/ssh/sshd_config.d/99-x.conf:3 », vide si rien ne la pose (un Match,
// une valeur par défaut d'OpenSSH).
func origine(racine, conf, cle string) string {
	contenu, _ := lireSiExiste(conf)
	for i, l := range lignes(contenu) {
		if strings.HasPrefix(l, PrefixeMarqueur) {
			return "" // le bloc commence : au-delà, c'est lui qui gagne
		}
		k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
		switch strings.ToLower(k) {
		case cle:
			return fmt.Sprintf("sshd_config:%d", i+1)
		case "include":
			for _, motif := range strings.Fields(v) {
				if !filepath.IsAbs(motif) {
					motif = filepath.Join("/etc/ssh", motif)
				}
				fichiers, _ := filepath.Glob(filepath.Join(racineDe(racine), motif))
				for _, f := range fichiers {
					inclus, _ := lireSiExiste(f)
					for j, li := range lignes(inclus) {
						if ki, _, _ := strings.Cut(strings.TrimSpace(li), " "); strings.ToLower(ki) == cle {
							return fmt.Sprintf("%s:%d", strings.TrimPrefix(f, strings.TrimSuffix(racine, "/")), j+1)
						}
					}
				}
			}
		case "match":
			return "" // la suite ne s'applique qu'à certaines connexions
		}
	}
	return ""
}

func racineDe(r string) string {
	if r == "" {
		return "/"
	}
	return r
}
