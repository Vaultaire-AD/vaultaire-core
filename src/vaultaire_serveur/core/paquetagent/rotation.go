package paquetagent

import (
	"crypto/rsa"
	"fmt"
	"sort"
	"strings"
)

// La rotation de pkg_signing — TO-DO 207.
//
// # Trois gestes, et pourquoi trois
//
//	1. ajouter   une clé SUIVANTE est tirée ; jeu n+1 = {active, suivante},
//	             signé par l'active. Les paquets restent signés par l'active.
//	2. basculer  quand le parc tient le jeu n+1 : la suivante devient l'active
//	             (les paquets sont désormais signés par elle), l'ancienne est
//	             gardée comme PRÉCÉDENTE.
//	3. retirer   jeu n+2 = {active}, signé par elle ; la précédente est oubliée.
//
// Entre 1 et 2, une machine qui n'a pas encore reçu le jeu n+1 accepte
// toujours les paquets : rien ne coupe une machine en retard. Basculer avant
// que le parc ait suivi la couperait de ses mises à jour jusqu'à ce qu'elle
// rattrape — d'où le refus, sauf --force.
//
// # La chaîne
//
// Le core GARDE tous les jeux publiés. Une machine qui demande avec le numéro
// N reçoit le plus petit jeu au-dessus de N : signé par une clé que le jeu N
// contient, puisque chaque jeu est signé par l'active du moment, présente dans
// le jeu précédent. Une machine éteinte pendant toute une rotation la rattrape
// jeu après jeu, sans geste de personne.
//
// # Compromission
//
// Hors bande (choix du 18/10) : une nouvelle active remplace tout, et son jeu
// est signé par ELLE — qu'aucune machine en service ne tient. Le canal ne peut
// donc pas l'imposer, et c'est voulu : qui détient l'ancienne clé pourrait en
// faire autant. Chaque machine reçoit le nouveau fichier par une réinstallation
// (« vlt create -c <id> -join »).

// Rôles des clés en magasin.
// SansCle : le numéro que déclare une machine sans pkg_signing_key.pem
// (TO-DO 233) — la même valeur que paquet.SansCle côté agent.
const SansCle = -1

const (
	RoleActive     = "active"
	RoleSuivante   = "suivante"
	RolePrecedente = "precedente"
)

// Phases d'une rotation.
const (
	PhaseStable   = "stable"
	PhaseAjoutee  = "ajoutée"
	PhaseBasculee = "basculée"
)

// CleStockee : une clé du magasin. Privee est nil en mode hors ligne.
type CleStockee struct {
	Publique *rsa.PublicKey
	Privee   *rsa.PrivateKey
}

// JeuStocke : un jeu publié, tel qu'il est servi.
type JeuStocke struct {
	Numero    int
	Corps     string
	Enveloppe string
}

// AgentJeu : une machine et le numéro du jeu qu'elle a déclaré tenir.
type AgentJeu struct {
	ComputeurID string
	Nom         string
	Numero      int
}

// Magasin : là où vivent les clés et les jeux (la base, en production).
type Magasin interface {
	Cle(role string) (CleStockee, bool, error)
	GenererSuivante() (CleStockee, error)
	Basculer() error
	OublierPrecedente() error
	// RemplacerCompromise tire une nouvelle active et efface toutes les autres.
	RemplacerCompromise() (CleStockee, error)
	DernierJeu() (JeuStocke, bool, error)
	JeuApres(n int) (JeuStocke, bool, error)
	AjouterJeu(j JeuStocke) error
	// Agents : les machines qui vérifient des paquets (agents Linux).
	Agents() ([]AgentJeu, error)
}

// EtatRotation : où en est le cluster.
type EtatRotation struct {
	Phase      string
	Jeu        int // dernier jeu publié, 0 : aucun (fichier de l'installation)
	Active     string
	Suivante   string
	Precedente string
	Agents     int
	AJour      int
	EnRetard   []AgentJeu
	// SansCle : les machines sans fichier de clés (TO-DO 233). Ni à jour ni
	// en retard : aucun jeu ne les rattrapera, il faut les réinstaller.
	SansCle       []AgentJeu
	ClesDuJeu     int
	ActiveEnLigne bool
}

// LireEtat décrit la rotation.
func LireEtat(m Magasin) (EtatRotation, error) {
	var e EtatRotation
	active, ok, err := m.Cle(RoleActive)
	if err != nil {
		return e, err
	}
	if !ok {
		return e, fmt.Errorf("aucune clé active : le core n'a jamais démarré sur cette base")
	}
	e.Active, _ = EmpreinteCle(active.Publique)
	e.ActiveEnLigne = active.Privee != nil
	e.Phase = PhaseStable
	if s, ok, err := m.Cle(RoleSuivante); err != nil {
		return e, err
	} else if ok {
		e.Suivante, _ = EmpreinteCle(s.Publique)
		e.Phase = PhaseAjoutee
	}
	if p, ok, err := m.Cle(RolePrecedente); err != nil {
		return e, err
	} else if ok {
		e.Precedente, _ = EmpreinteCle(p.Publique)
		e.Phase = PhaseBasculee
	}
	if j, ok, err := m.DernierJeu(); err != nil {
		return e, err
	} else if ok {
		e.Jeu = j.Numero
		if lu, err := LireJeu(j.Corps); err == nil {
			e.ClesDuJeu = len(lu.Cles)
		}
	} else {
		e.ClesDuJeu = 1
	}
	agents, err := m.Agents()
	if err != nil {
		return e, err
	}
	e.Agents = len(agents)
	for _, a := range agents {
		if a.Numero == SansCle {
			e.SansCle = append(e.SansCle, a)
			continue
		}
		if a.Numero >= e.Jeu {
			e.AJour++
		} else {
			e.EnRetard = append(e.EnRetard, a)
		}
	}
	sort.Slice(e.EnRetard, func(i, j int) bool { return e.EnRetard[i].Nom < e.EnRetard[j].Nom })
	sort.Slice(e.SansCle, func(i, j int) bool { return e.SansCle[i].Nom < e.SansCle[j].Nom })
	return e, nil
}

// signataire : la clé privée de l'active, en base ou fournie hors ligne —
// auquel cas elle doit ÊTRE l'active.
func signataire(active CleStockee, horsLigne *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if horsLigne != nil {
		a, _ := EmpreinteCle(active.Publique)
		f, _ := EmpreinteCle(&horsLigne.PublicKey)
		if a != f {
			return nil, fmt.Errorf("la clé fournie (%s) n'est pas l'active (%s)", f, a)
		}
		return horsLigne, nil
	}
	if active.Privee == nil {
		return nil, fmt.Errorf("la clé privée active n'est pas sur ce core (mode hors ligne) : ajoutez --key <fichier>")
	}
	return active.Privee, nil
}

func publier(m Magasin, j Jeu, signe *rsa.PrivateKey) (JeuStocke, error) {
	corps, env, err := SignerJeu(j, signe)
	if err != nil {
		return JeuStocke{}, err
	}
	if _, err := VerifierJeu(corps, env, []*rsa.PublicKey{&signe.PublicKey}); err != nil {
		return JeuStocke{}, fmt.Errorf("relecture du jeu : %w", err)
	}
	s := JeuStocke{Numero: j.Numero, Corps: corps, Enveloppe: env.Texte()}
	return s, m.AjouterJeu(s)
}

func prochainNumero(m Magasin) (int, error) {
	d, ok, err := m.DernierJeu()
	if err != nil || !ok {
		return 1, err
	}
	return d.Numero + 1, nil
}

// Ajouter : geste 1.
func Ajouter(m Magasin, horsLigne *rsa.PrivateKey) (JeuStocke, error) {
	e, err := LireEtat(m)
	if err != nil {
		return JeuStocke{}, err
	}
	if e.Phase != PhaseStable {
		return JeuStocke{}, fmt.Errorf("une rotation est en cours (%s) : terminez-la avant d'en ouvrir une autre", e.Phase)
	}
	active, _, _ := m.Cle(RoleActive)
	signe, err := signataire(active, horsLigne)
	if err != nil {
		return JeuStocke{}, err
	}
	n, err := prochainNumero(m)
	if err != nil {
		return JeuStocke{}, err
	}
	suivante, err := m.GenererSuivante()
	if err != nil {
		return JeuStocke{}, err
	}
	return publier(m, Jeu{Numero: n, Cles: []*rsa.PublicKey{active.Publique, suivante.Publique}}, signe)
}

// ErrParcEnRetard : basculer couperait des machines de leurs mises à jour.
type ErrParcEnRetard struct {
	Jeu      int
	EnRetard []AgentJeu
}

func (e *ErrParcEnRetard) Error() string {
	var noms []string
	for i, a := range e.EnRetard {
		if i == 10 {
			noms = append(noms, fmt.Sprintf("… et %d autre(s)", len(e.EnRetard)-10))
			break
		}
		noms = append(noms, fmt.Sprintf("%s (jeu n°%d)", a.Nom, a.Numero))
	}
	return fmt.Sprintf("%d agent(s) ne tiennent pas encore le jeu n°%d — basculer maintenant leur ferait "+
		"refuser les paquets jusqu'à ce qu'ils le reçoivent : %s. Attendez (un agent le demande à chaque "+
		"connexion et toutes les heures), ou --force", len(e.EnRetard), e.Jeu, strings.Join(noms, ", "))
}

// Basculer : geste 2.
func Basculer(m Magasin, force bool) error {
	e, err := LireEtat(m)
	if err != nil {
		return err
	}
	if e.Phase != PhaseAjoutee {
		return fmt.Errorf("rien à basculer (phase %s) : « rotate-add » d'abord", e.Phase)
	}
	if len(e.EnRetard) > 0 && !force {
		return &ErrParcEnRetard{Jeu: e.Jeu, EnRetard: e.EnRetard}
	}
	return m.Basculer()
}

// Retirer : geste 3.
func Retirer(m Magasin, horsLigne *rsa.PrivateKey) (JeuStocke, error) {
	e, err := LireEtat(m)
	if err != nil {
		return JeuStocke{}, err
	}
	if e.Phase != PhaseBasculee {
		return JeuStocke{}, fmt.Errorf("rien à retirer (phase %s) : « rotate-switch » d'abord", e.Phase)
	}
	active, _, _ := m.Cle(RoleActive)
	signe, err := signataire(active, horsLigne)
	if err != nil {
		return JeuStocke{}, err
	}
	n, err := prochainNumero(m)
	if err != nil {
		return JeuStocke{}, err
	}
	s, err := publier(m, Jeu{Numero: n, Cles: []*rsa.PublicKey{active.Publique}}, signe)
	if err != nil {
		return JeuStocke{}, err
	}
	return s, m.OublierPrecedente()
}

// Compromise : la clé active (ou une autre) a fuité. Voir l'en-tête.
func Compromise(m Magasin) (JeuStocke, error) {
	n, err := prochainNumero(m)
	if err != nil {
		return JeuStocke{}, err
	}
	nouvelle, err := m.RemplacerCompromise()
	if err != nil {
		return JeuStocke{}, err
	}
	if nouvelle.Privee == nil {
		return JeuStocke{}, fmt.Errorf("nouvelle clé sans partie privée")
	}
	return publier(m, Jeu{Numero: n, Cles: []*rsa.PublicKey{nouvelle.Publique}}, nouvelle.Privee)
}

// JeuDeLInstallation : ce que reçoit une machine qu'on installe — le dernier
// jeu publié, ou la seule clé active (numéro 0) s'il n'y en a pas.
func JeuDeLInstallation(m Magasin) (Jeu, error) {
	if d, ok, err := m.DernierJeu(); err != nil {
		return Jeu{}, err
	} else if ok {
		return LireJeu(d.Corps)
	}
	active, ok, err := m.Cle(RoleActive)
	if err != nil || !ok {
		return Jeu{}, fmt.Errorf("aucune clé active : %v", err)
	}
	return Jeu{Numero: 0, Cles: []*rsa.PublicKey{active.Publique}}, nil
}
