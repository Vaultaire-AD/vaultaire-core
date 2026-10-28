package confsys

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// La réconciliation — TO-DO 117.
//
// Pour chaque fichier tenu : lire son marqueur ; à jour, rien ; en avance,
// rien ; sinon produire le candidat, le CONTRÔLER (porte de secours, sshd -t),
// le sauvegarder sous « <fichier>.vaultaire-bak-<horodatage> », et le poser par
// rename() dans son répertoire. Par groupe, tout ou rien.

// Etats du compte rendu (09_07). Les MÊMES chaînes côté core
// (core/confsys), figées par des tests jumeaux.
const (
	EtatConforme        = "conforme"
	EtatReconciliee     = "reconciliee"
	EtatEcart           = "ecart"
	EtatDesactivee      = "desactivee"
	EtatNonPrisEnCharge = "non_pris_en_charge"
)

// Systeme lance une commande. Remplaçable par les tests.
type Systeme func(nom string, args ...string) ([]byte, error)

// Env : ce dont la réconciliation a besoin.
type Env struct {
	Racine  string // "" en production ; un répertoire de test sinon
	Famille string
	Systeme Systeme
	Horloge func() time.Time
	// DossierSauvegardes : celles qui ne vont pas à côté de leur fichier.
	DossierSauvegardes string
}

func (e Env) chemin(rel string) string { return filepath.Join(e.racine(), rel) }
func (e Env) racine() string {
	if e.Racine == "" {
		return "/"
	}
	return e.Racine
}

// Constat : ce qu'il en est d'un fichier.
type Constat struct {
	Nom      string
	Groupe   string
	Avant    int // version trouvée, 0 sans marqueur
	Attendue int
	Action   string // voir les constantes Action…
	Detail   string
}

const (
	ActionAJour    = "à jour"
	ActionEnAvance = "en avance"
	ActionAbsent   = "absent"
	ActionAEcrire  = "à écrire"
	ActionEcrit    = "écrit"
	ActionRefuse   = "refusé"
)

// Rapport : le résultat d'un passage.
type Rapport struct {
	Etat     string
	Motif    string
	Constats []Constat
}

type candidat struct {
	regle   Regle
	chemin  string
	contenu string
	existe  bool
	mode    fs.FileMode
	uid     int
	gid     int
	tmp     string
	bak     string
}

// Planifier lit sans rien écrire : ce que Reconcilier ferait. Les candidats
// sont rangés par groupe ; un groupe en erreur n'a pas de candidats.
func Planifier(e Env) (Rapport, map[string][]candidat, error) {
	_, avecGDM := lireSiExiste(e.chemin("etc/pam.d/gdm-password"))
	regles, err := Regles(e.Famille, avecGDM)
	if err != nil {
		return Rapport{}, nil, err
	}
	var r Rapport
	parGroupe := map[string][]candidat{}
	enErreur := map[string]bool{}
	for _, g := range regles {
		ch := e.chemin(g.Rel)
		k := Constat{Nom: g.Nom, Groupe: g.Groupe, Attendue: g.Version}
		actuel, existe := lireSiExiste(ch)
		if !existe && !g.Creer {
			if g.Requis {
				k.Action, k.Detail = ActionRefuse, "fichier absent"
				enErreur[g.Groupe] = true
			} else {
				k.Action = ActionAbsent
			}
			r.Constats = append(r.Constats, k)
			continue
		}
		k.Avant = LireVersion(actuel)
		switch {
		case existe && k.Avant == g.Version:
			k.Action = ActionAJour
		case existe && k.Avant > g.Version:
			k.Action, k.Detail = ActionEnAvance, "laissé tel quel : on ne descend pas une configuration"
		default:
			contenu, err := g.Produire(actuel)
			if err == nil && g.Verifier != nil {
				err = g.Verifier(contenu)
			}
			if err != nil {
				k.Action, k.Detail = ActionRefuse, err.Error()
				enErreur[g.Groupe] = true
				break
			}
			c := candidat{regle: g, chemin: ch, contenu: contenu, existe: existe, mode: 0o644}
			if info, err := os.Stat(ch); err == nil {
				c.mode = info.Mode().Perm()
				if st, ok := info.Sys().(*syscall.Stat_t); ok {
					c.uid, c.gid = int(st.Uid), int(st.Gid)
				}
			}
			k.Action = ActionAEcrire
			parGroupe[g.Groupe] = append(parGroupe[g.Groupe], c)
		}
		r.Constats = append(r.Constats, k)
	}
	for g := range enErreur {
		delete(parGroupe, g)
	}
	return r, parGroupe, nil
}

// Reconcilier fait le passage, et rend son rapport.
func Reconcilier(e Env) Rapport {
	r, parGroupe, err := Planifier(e)
	if err != nil {
		return Rapport{Etat: EtatNonPrisEnCharge, Motif: err.Error()}
	}
	ecrits := map[string]bool{}
	groupes := make([]string, 0, len(parGroupe))
	for g := range parGroupe {
		groupes = append(groupes, g)
	}
	sort.Strings(groupes)
	for _, g := range groupes {
		if err := e.ecrireGroupe(parGroupe[g]); err != nil {
			marquer(&r, g, ActionAEcrire, ActionRefuse, err.Error())
			continue
		}
		marquer(&r, g, ActionAEcrire, ActionEcrit, "")
		for _, c := range parGroupe[g] {
			ecrits[c.regle.Apres] = true
		}
	}
	if ecrits[apresSSHD] {
		if sortie, err := e.Systeme("systemctl", "try-reload-or-restart", ServiceSSH(e.Famille)+".service"); err != nil {
			r.Constats = append(r.Constats, Constat{Nom: "service " + ServiceSSH(e.Famille), Action: "non rechargé",
				Detail: "la configuration, validée, sera lue au prochain démarrage : " + premieresLignes(string(sortie), 2)})
		}
	}
	if ecrits[apresDconf] {
		_, _ = e.Systeme("dconf", "update")
	}
	// Ce que sshd applique vraiment (TO-DO 209) : lu après l'écriture, sur le
	// fichier en place — y compris quand sa réécriture a été refusée.
	if k := ControlerSSHDEffectif(e); k != nil {
		r.Constats = append(r.Constats, *k)
	}
	r.Etat, r.Motif = resumer(r.Constats)
	return r
}

func marquer(r *Rapport, groupe, de, vers, detail string) {
	for i := range r.Constats {
		if r.Constats[i].Groupe == groupe && r.Constats[i].Action == de {
			r.Constats[i].Action = vers
			if detail != "" {
				r.Constats[i].Detail = detail
			}
		}
	}
}

// ecrireGroupe : candidats posés dans leur répertoire, contrôlés, sauvegardés,
// puis renommés — et, au premier renommage qui échoue, les précédents remis.
func (e Env) ecrireGroupe(cs []candidat) (err error) {
	defer func() {
		for _, c := range cs {
			if c.tmp != "" {
				_ = os.Remove(c.tmp)
			}
		}
	}()
	horodatage := e.Horloge().Format("20060102-150405")
	for i := range cs {
		c := &cs[i]
		if err := os.MkdirAll(filepath.Dir(c.chemin), 0o755); err != nil {
			return err
		}
		f, err := os.CreateTemp(filepath.Dir(c.chemin), "."+filepath.Base(c.chemin)+".vaultaire-*")
		if err != nil {
			return fmt.Errorf("%s : %w", c.regle.Nom, err)
		}
		c.tmp = f.Name()
		_, errW := f.WriteString(c.contenu)
		errS := f.Sync()
		errC := f.Close()
		if errW != nil || errS != nil || errC != nil {
			return fmt.Errorf("%s : écriture du candidat : %v %v %v", c.regle.Nom, errW, errS, errC)
		}
		if err := os.Chmod(c.tmp, c.mode); err != nil {
			return err
		}
		if c.existe {
			_ = os.Chown(c.tmp, c.uid, c.gid)
		}
		if c.regle.ValiderSSHD {
			if sortie, err := e.Systeme("sshd", "-t", "-f", c.tmp); err != nil {
				return fmt.Errorf("sshd -t refuse la configuration produite : %s", premieresLignes(string(sortie), 3))
			}
		}
	}
	for i := range cs {
		c := &cs[i]
		if !c.existe {
			continue
		}
		dossier := filepath.Dir(c.chemin)
		if c.regle.SauvegardeAilleurs {
			dossier = e.DossierSauvegardes
			if err := os.MkdirAll(dossier, 0o700); err != nil {
				return err
			}
		}
		c.bak = filepath.Join(dossier, filepath.Base(c.chemin)+".vaultaire-bak-"+horodatage)
		if err := copierFichier(c.chemin, c.bak); err != nil {
			return fmt.Errorf("%s : sauvegarde impossible, rien n'est touché : %w", c.regle.Nom, err)
		}
	}
	for i := range cs {
		if err := os.Rename(cs[i].tmp, cs[i].chemin); err != nil {
			cause := fmt.Sprintf("%s : %v", cs[i].regle.Nom, err)
			if echecs := remettre(cs[:i]); len(echecs) > 0 {
				return fmt.Errorf("%s — REMISE INCOMPLÈTE : %s", cause, strings.Join(echecs, " ; "))
			}
			return fmt.Errorf("%s — les fichiers déjà posés du groupe sont remis", cause)
		}
		cs[i].tmp = ""
	}
	args := []string{"-F"}
	for _, c := range cs {
		args = append(args, c.chemin)
	}
	_, _ = e.Systeme("restorecon", args...)
	return nil
}

// remettre rend leur sauvegarde aux fichiers déjà posés ; un fichier créé
// (sans sauvegarde) est retiré.
func remettre(cs []candidat) []string {
	var echecs []string
	for _, c := range cs {
		var err error
		if c.bak == "" {
			err = os.Remove(c.chemin)
		} else {
			err = restaurer(c.bak, c.chemin)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			echecs = append(echecs, c.regle.Nom+" : "+err.Error())
		}
	}
	return echecs
}

// resumer : l'état, et un motif d'une ligne pour le core.
func resumer(ks []Constat) (string, string) {
	var ecrits, refus, avance []string
	for _, k := range ks {
		switch k.Action {
		case ActionEcrit:
			ecrits = append(ecrits, fmt.Sprintf("%s v%d→v%d", k.Nom, k.Avant, k.Attendue))
		case ActionRefuse, ActionEcartEffectif:
			refus = append(refus, k.Nom+" : "+k.Detail)
		case ActionEnAvance:
			avance = append(avance, fmt.Sprintf("%s v%d (en avance)", k.Nom, k.Avant))
		case "non rechargé":
			refus = append(refus, k.Nom+" non rechargé")
		}
	}
	var morceaux []string
	if len(refus) > 0 {
		morceaux = append(morceaux, "refusé : "+strings.Join(refus, " ; "))
	}
	if len(ecrits) > 0 {
		morceaux = append(morceaux, "écrit : "+strings.Join(ecrits, ", "))
	}
	if len(avance) > 0 {
		morceaux = append(morceaux, strings.Join(avance, ", "))
	}
	motif := strings.Join(morceaux, " — ")
	switch {
	case len(refus) > 0:
		return EtatEcart, motif
	case len(ecrits) > 0:
		return EtatReconciliee, motif
	}
	if motif == "" {
		motif = "tous les fichiers à la version de l'agent"
	}
	return EtatConforme, motif
}

func lireSiExiste(chemin string) (string, bool) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// copierFichier : contenu, mode, et propriétaire si possible.
func copierFichier(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, b, info.Mode().Perm()); err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(dst, int(st.Uid), int(st.Gid))
	}
	return nil
}

func premieresLignes(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, " / ")
}

// restaurer remet une sauvegarde par le même chemin qu'une écriture : un
// fichier temporaire dans le répertoire, puis rename().
func restaurer(bak, dst string) error {
	tmp := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".vaultaire-remise")
	if err := copierFichier(bak, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
