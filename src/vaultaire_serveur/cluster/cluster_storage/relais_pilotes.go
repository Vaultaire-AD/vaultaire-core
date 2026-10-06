package clusterstorage

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Les relais d'un proxy, tels que le core les DEMANDE et tels que le proxy les
// RAPPORTE — TO-DO 141.
//
// # Ce qui manquait
//
// Ce qu'un proxy expose — Ducky, HTTPS, LDAPS, sur quel port, vers quoi — ne
// s'écrivait que dans le fichier YAML du proxy. Le core n'en savait que des
// compteurs (TO-DO 108) : il ne pouvait ni dire vers quoi un relais redirige,
// ni en changer un. Ajouter un relais à un site demandait une session sur la
// machine du proxy et un redémarrage, donc la coupure de tous les tunnels
// qu'il transportait.
//
// # Le format vient du protocole
//
// Les étiquettes JSON sont celles des trames 04_18 (le proxy rend compte) et
// 04_19 (le core demande). Le proxy vit dans un autre module et ne partage
// aucun code avec celui-ci : c'est un format de PROTOCOLE, au même titre qu'un
// numéro de trame, et le changer d'un seul côté vide la vue ou fait refuser la
// liste. Elles reprennent les clés du fichier YAML du proxy, à dessein : un
// relais se décrit de la même façon partout.
//
// Un champ absent vaut zéro, des deux côtés.

// Types de relais.
const (
	RelaisDucky = "ducky"
	RelaisHTTPS = "https"
	RelaisLDAPS = "ldaps"
	// RelaisLDAP est RECONNU pour être refusé avec sa raison, et non confondu
	// avec une faute de frappe.
	RelaisLDAP = "ldap"
)

// MotifLDAPEnClair dit pourquoi le relais LDAP en clair n'existe pas.
const MotifLDAPEnClair = "relayé, LDAP en clair ferait voyager les mots de passe en clair du site " +
	"jusqu'au core, et le core n'implémente pas StartTLS — employez « ldaps »"

// Sources de cibles.
const (
	SourceCores   = "cores"
	SourceListe   = "liste"
	SourceService = "service:"
)

// portRelaisParDefaut est le port d'écoute quand la demande n'en donne pas.
var portRelaisParDefaut = map[string]int{RelaisDucky: 6666, RelaisHTTPS: 443, RelaisLDAPS: 636}

// CiblesRelais dit vers qui un relais transporte.
type CiblesRelais struct {
	Source   string   `json:"source"`
	Adresses []string `json:"adresses,omitempty"`
	// Port : pour la source « cores », le port à joindre sur chaque core.
	Port int `json:"port,omitempty"`
}

// RelaisConfig est la configuration d'un relais.
type RelaisConfig struct {
	Nom    string       `json:"nom"`
	Type   string       `json:"type"`
	Ecoute string       `json:"ecoute"`
	Cibles CiblesRelais `json:"cibles"`

	// Zéro vaut « le défaut du proxy » pour les quatre.
	DelaiConnexionSecondes int `json:"delai_connexion_secondes,omitempty"`
	InactiviteSecondes     int `json:"inactivite_secondes,omitempty"`
	MaxConnexions          int `json:"max_connexions,omitempty"`
	MaxParSource           int `json:"max_par_source,omitempty"`
}

// DemandeRelais est le document d'une 04_19.
type DemandeRelais struct {
	Relais []RelaisConfig `json:"relais"`
}

// Encoder rend la demande sur une ligne.
func (d DemandeRelais) Encoder() string {
	if d.Relais == nil {
		d.Relais = []RelaisConfig{}
	}
	b, err := json.Marshal(d)
	if err != nil {
		return `{"relais":[]}`
	}
	return string(b)
}

// Statuts qu'un proxy rapporte pour un relais.
const (
	StatutRelaisActif  = "actif"
	StatutRelaisRefuse = "refuse"
)

// Origines de la configuration qu'un proxy applique.
const (
	OrigineFichier = "fichier"
	OrigineCore    = "core"
)

// RelaisRapporte est un relais dans le compte rendu d'un proxy.
type RelaisRapporte struct {
	RelaisConfig

	Statut          string   `json:"statut"`
	Motif           string   `json:"motif,omitempty"`
	EcouteEffective string   `json:"ecoute_effective,omitempty"`
	CiblesResolues  []string `json:"cibles_resolues,omitempty"`
}

// CompteRenduRelais est le document d'une 04_18.
type CompteRenduRelais struct {
	Version int `json:"v"`

	// Revision est celle de la liste du core que le proxy applique. Zéro : il
	// applique son fichier.
	Revision int    `json:"revision"`
	Origine  string `json:"origine"`

	// Pilotage : le proxy accepte d'être piloté. Faux quand son fichier porte
	// « pilotage_par_le_core: false ».
	Pilotage bool `json:"pilotage"`

	// PortAnnonce est le port Ducky que le proxy a annoncé au cluster : celui
	// que son relais Ducky doit garder.
	PortAnnonce int `json:"port_annonce"`

	// RevisionRefusee et Refus : la dernière liste refusée EN ENTIER.
	RevisionRefusee int    `json:"revision_refusee,omitempty"`
	Refus           string `json:"refus,omitempty"`

	Relais []RelaisRapporte `json:"relais"`

	// Recu est l'heure d'enregistrement par le core. Elle dit DEPUIS QUAND on
	// regarde cet état : un proxy silencieux depuis une heure n'applique
	// peut-être plus ce qu'il a rapporté.
	Recu time.Time `json:"-"`
}

// TailleMaxCompteRendu borne le document d'une 04_18.
//
// Il est écrit par un proxy et gardé en base tel quel. Une trame Ducky ne
// dépasse pas 64 Ko ; trente-deux laissent la place d'une centaine de relais
// et ferment la porte à un document qui n'en serait pas un.
const TailleMaxCompteRendu = 32 * 1024

// MaxRelaisParProxy borne le nombre de relais d'un proxy.
const MaxRelaisParProxy = 32

// DecoderCompteRendu lit le document d'une 04_18.
func DecoderCompteRendu(document string) (CompteRenduRelais, error) {
	if len(document) > TailleMaxCompteRendu {
		return CompteRenduRelais{}, fmt.Errorf("compte rendu de %d octets, au-delà des %d admis",
			len(document), TailleMaxCompteRendu)
	}
	var c CompteRenduRelais
	if err := json.Unmarshal([]byte(document), &c); err != nil {
		return CompteRenduRelais{}, fmt.Errorf("compte rendu illisible : %w", err)
	}
	if len(c.Relais) > MaxRelaisParProxy {
		return CompteRenduRelais{}, fmt.Errorf("%d relais rapportés, au-delà des %d admis", len(c.Relais), MaxRelaisParProxy)
	}
	if c.Origine != OrigineCore {
		// Tout ce qui n'est pas « core » est le fichier : une origine inconnue
		// ne doit pas se lire comme une liste que le core aurait posée.
		c.Origine = OrigineFichier
	}
	return c, nil
}

// --- contrôle d'une demande ----------------------------------------------------

// nomDeRelais : lettres, chiffres, point, tiret, souligné. Le nom désigne le
// relais dans les commandes, dans l'adresse de la page et dans le journal du
// proxy ; rien de ce qui se glisserait dans l'un des trois n'y a sa place.
var nomDeRelais = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,47}$`)

// Bornes des quatre réglages facultatifs. Zéro — « le défaut du proxy » —
// reste toujours admis.
const (
	MaxDelaiConnexionSecondes = 120
	MinInactiviteSecondes     = 10
	MaxInactiviteSecondes     = 24 * 3600
	MaxConnexionsAdmises      = 100000
)

// TypeDeService rend le type de service d'une source « service:… », ou "".
func (r RelaisConfig) TypeDeService() string {
	if strings.HasPrefix(r.Cibles.Source, SourceService) {
		return strings.TrimSpace(strings.TrimPrefix(r.Cibles.Source, SourceService))
	}
	return ""
}

// PortDEcoute rend le port de l'adresse d'écoute, ou "" si elle est illisible.
func (r RelaisConfig) PortDEcoute() string {
	_, p, err := net.SplitHostPort(r.Ecoute)
	if err != nil {
		return ""
	}
	return p
}

// Valider contrôle un relais demandé et pose ses défauts.
//
// # Les mêmes règles que le proxy, écrites deux fois
//
// Le proxy contrôle de son côté tout ce qu'il reçoit — c'est lui qui ouvre les
// ports. Ce contrôle-ci ne le remplace pas : il sert à refuser TOUT DE SUITE,
// à l'administrateur qui tape, ce que le proxy refuserait une minute plus tard
// sans personne pour lire le motif. Si les deux divergent, le proxy tranche,
// et son refus remonte dans le compte rendu.
func (r *RelaisConfig) Valider() error {
	r.Type = strings.ToLower(strings.TrimSpace(r.Type))
	r.Nom = strings.TrimSpace(r.Nom)
	r.Ecoute = strings.TrimSpace(r.Ecoute)
	r.Cibles.Source = strings.TrimSpace(r.Cibles.Source)

	switch r.Type {
	case RelaisDucky, RelaisHTTPS, RelaisLDAPS:
	case RelaisLDAP:
		return fmt.Errorf("relais de type « ldap » refusé : %s", MotifLDAPEnClair)
	case "":
		return fmt.Errorf("type de relais requis (ducky, https, ldaps)")
	default:
		return fmt.Errorf("type de relais %q inconnu (ducky, https, ldaps)", r.Type)
	}

	if r.Nom == "" {
		r.Nom = r.Type
	}
	if !nomDeRelais.MatchString(r.Nom) {
		return fmt.Errorf("nom de relais %q invalide : lettres, chiffres, « . », « - » et « _ », 48 caractères au plus", r.Nom)
	}

	if r.Ecoute == "" {
		r.Ecoute = ":" + strconv.Itoa(portRelaisParDefaut[r.Type])
	}
	// « 8843 » seul est une saisie naturelle : on l'entend comme « :8843 ».
	if _, err := strconv.Atoi(r.Ecoute); err == nil {
		r.Ecoute = ":" + r.Ecoute
	}
	hote, port, err := net.SplitHostPort(r.Ecoute)
	if err != nil {
		return fmt.Errorf("relais %q : écoute %q invalide (attendu « [adresse]:port »)", r.Nom, r.Ecoute)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("relais %q : port d'écoute %q invalide (1 à 65535)", r.Nom, port)
	}
	if hote != "" && net.ParseIP(hote) == nil {
		return fmt.Errorf("relais %q : l'adresse d'écoute %q n'est pas une adresse IP — "+
			"laissez-la vide pour écouter sur toutes les interfaces du proxy", r.Nom, hote)
	}

	if r.Cibles.Source == "" {
		if r.Type == RelaisHTTPS {
			return fmt.Errorf("relais %q : un relais https doit nommer ses cibles — "+
				"source « service:vaultaire_nexus » ou « liste »", r.Nom)
		}
		r.Cibles.Source = SourceCores
	}
	if r.Cibles.Port != 0 {
		if r.Cibles.Source != SourceCores {
			return fmt.Errorf("relais %q : le port cible ne vaut que pour la source « cores » — "+
				"une liste porte déjà le port de chaque adresse", r.Nom)
		}
		if r.Cibles.Port < 1 || r.Cibles.Port > 65535 {
			return fmt.Errorf("relais %q : port cible %d invalide", r.Nom, r.Cibles.Port)
		}
	}

	switch {
	case r.Cibles.Source == SourceCores:
		if r.Type == RelaisHTTPS {
			return fmt.Errorf("relais %q : la source « cores » donne les adresses Ducky des cores, "+
				"pas un service HTTPS — employez « service:<type> » ou « liste »", r.Nom)
		}
		r.Cibles.Adresses = nil
	case r.Cibles.Source == SourceListe:
		var propres []string
		for _, a := range r.Cibles.Adresses {
			if a = strings.TrimSpace(a); a == "" {
				continue
			}
			h, p, err := net.SplitHostPort(a)
			n, errPort := strconv.Atoi(p)
			if err != nil || h == "" || errPort != nil || n < 1 || n > 65535 {
				return fmt.Errorf("relais %q : cible %q invalide (attendu « hôte:port »)", r.Nom, a)
			}
			propres = append(propres, a)
		}
		if len(propres) == 0 {
			return fmt.Errorf("relais %q : source « liste » sans adresse", r.Nom)
		}
		if len(propres) > 32 {
			return fmt.Errorf("relais %q : %d cibles, 32 au plus", r.Nom, len(propres))
		}
		r.Cibles.Adresses = propres
	case strings.HasPrefix(r.Cibles.Source, SourceService):
		if r.Type != RelaisHTTPS {
			return fmt.Errorf("relais %q : la source %q ne sert qu'au relais https — un %s relaie vers les cores",
				r.Nom, r.Cibles.Source, r.Type)
		}
		typ := r.TypeDeService()
		if typ == "" {
			return fmt.Errorf("relais %q : source « service: » sans type (ex. « service:vaultaire_nexus »)", r.Nom)
		}
		r.Cibles.Source = SourceService + typ
		r.Cibles.Adresses = nil
	default:
		return fmt.Errorf("relais %q : source de cibles %q inconnue (cores, liste, service:<type>)", r.Nom, r.Cibles.Source)
	}

	if d := r.DelaiConnexionSecondes; d < 0 || d > MaxDelaiConnexionSecondes {
		return fmt.Errorf("relais %q : délai de connexion de %d s refusé, attendu de 1 à %d (0 : le défaut du proxy)",
			r.Nom, d, MaxDelaiConnexionSecondes)
	}
	if d := r.InactiviteSecondes; d != 0 && (d < MinInactiviteSecondes || d > MaxInactiviteSecondes) {
		return fmt.Errorf("relais %q : inactivité de %d s refusée, attendu de %d à %d (0 : le défaut du proxy)",
			r.Nom, d, MinInactiviteSecondes, MaxInactiviteSecondes)
	}
	if n := r.MaxConnexions; n < 0 || n > MaxConnexionsAdmises {
		return fmt.Errorf("relais %q : plafond de %d connexions refusé, attendu de 1 à %d (0 : le défaut du proxy)",
			r.Nom, n, MaxConnexionsAdmises)
	}
	if n := r.MaxParSource; n < 0 || n > MaxConnexionsAdmises {
		return fmt.Errorf("relais %q : plafond de %d connexions par source refusé, attendu de 1 à %d (0 : le défaut du proxy)",
			r.Nom, n, MaxConnexionsAdmises)
	}
	return nil
}

// ValiderListeDeRelais contrôle la liste ENTIÈRE qu'on s'apprête à demander à
// un proxy, et rend la première faute.
//
// portAnnonce est le port Ducky que le proxy a déclaré au cluster ; zéro s'il
// est inconnu, et la règle du port n'est alors pas contrôlée ici — le proxy,
// lui, la contrôlera.
//
// # Le relais Ducky ne se retire pas, et ne change pas de port
//
// Le proxy est annoncé aux agents comme un nœud Ducky, sur ce port-là. Une
// liste sans relais Ducky en ferait un trou noir : les agents s'y
// présenteraient et rien ne répondrait. Le port vient du démarrage du proxy
// (-listen-port) et de ce que le cluster distribue ; le changer d'ici
// désaccorderait les deux.
func ValiderListeDeRelais(liste []RelaisConfig, portAnnonce int) error {
	if len(liste) > MaxRelaisParProxy {
		return fmt.Errorf("%d relais demandés, %d au plus par proxy", len(liste), MaxRelaisParProxy)
	}
	noms := map[string]bool{}
	ecoutes := map[string]string{}
	ducky := 0
	for i := range liste {
		r := &liste[i]
		if err := r.Valider(); err != nil {
			return err
		}
		cle := strings.ToLower(r.Nom)
		if noms[cle] {
			return fmt.Errorf("relais %q déclaré deux fois", r.Nom)
		}
		noms[cle] = true
		port := r.PortDEcoute()
		if autre, pris := ecoutes[port]; pris {
			// Par PORT, et non par adresse complète : « :8843 » et
			// « 10.0.0.5:8843 » se disputent le même port sur la machine.
			return fmt.Errorf("les relais %q et %q écoutent tous deux sur le port %s", autre, r.Nom, port)
		}
		ecoutes[port] = r.Nom
		if r.Type == RelaisDucky {
			ducky++
			if portAnnonce > 0 && port != strconv.Itoa(portAnnonce) {
				return fmt.Errorf("relais Ducky %q sur le port %s, alors que ce proxy est annoncé aux agents sur le port %d : "+
					"ce port vient du démarrage du proxy (-listen-port) et ne se change pas d'ici", r.Nom, port, portAnnonce)
			}
		}
	}
	switch {
	case ducky == 0:
		return fmt.Errorf("la liste ne porte aucun relais Ducky : ce proxy est annoncé aux agents comme un nœud Ducky, " +
			"et sans ce relais ils s'y présenteraient pour rien")
	case ducky > 1:
		return fmt.Errorf("%d relais Ducky demandés : un seul port est annoncé aux agents", ducky)
	}
	return nil
}

// DepuisLeCompteRendu rend la configuration des relais ACTIFS d'un compte
// rendu : c'est la base sur laquelle le core prend la main la première fois.
//
// Les quatre réglages facultatifs y sont repris tels que le proxy les
// rapporte, donc avec ses défauts résolus : la première révision fige ce qui
// tournait, à l'identique.
func DepuisLeCompteRendu(c CompteRenduRelais) []RelaisConfig {
	out := make([]RelaisConfig, 0, len(c.Relais))
	for _, r := range c.Relais {
		if r.Statut == StatutRelaisActif {
			out = append(out, r.RelaisConfig)
		}
	}
	return out
}
