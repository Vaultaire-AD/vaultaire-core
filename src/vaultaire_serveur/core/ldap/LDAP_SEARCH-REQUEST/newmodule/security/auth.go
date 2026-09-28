package security

import (
	"fmt"
	"strings"
	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	domainpkg "vaultaire/core/domain"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

// PorteeDeRecherche porte les domaines qu'un compte a le droit de lire.
//
// # Le défaut qu'elle ferme
//
// Le contrôle d'accès à la recherche tenait en UN appel, sur le seul baseDN
// demandé. Le résolveur, lui, charge le domaine ET tous ses sous-domaines
// (`GetGroupsUnderDomain` retient `HasSuffix(dn, "."+cible)`), et aucun filtrage
// ne suivait.
//
// Conséquence : un compte portant `search` en « custom SANS propagation » sur
// `enov.local` passait le contrôle, puis recevait dans la même réponse les
// comptes et les groupes de `admin.enov.local`. Le mode « sans propagation » —
// dont c'est la seule raison d'être — n'avait aucun effet sur le chemin LDAP.
//
// # Pourquoi un objet, et non un appel par entrée
//
// `IsAuthorizedToSearch` lisait la base à chaque appel. L'appeler une fois par
// entrée aurait ajouté une requête SQL par compte rendu, sur le chemin le plus
// chaud du serveur — une recherche porte couramment sur des milliers d'entrées.
//
// Les permissions sont donc lues UNE fois, au début de la recherche, et la
// décision par domaine est du pur travail de chaîne, mémorisé : un annuaire a
// quelques domaines, pas quelques milliers.
type PorteeDeRecherche struct {
	// actions : les permissions ANALYSÉES, dont les domaines ont été normalisés.
	//
	// Analysées à la construction, et non à chaque interrogation : l'analyse
	// découpe des chaînes, la décision ne fait plus que comparer.
	actions []storage.PermissionAction
	// decisions mémorise la réponse par domaine. Une recherche ramène des
	// milliers d'entrées réparties sur une poignée de domaines : sans cela, la
	// même liste d'actions serait re-parcourue à chaque entrée.
	//
	// Sans verrou : une portée appartient à UNE recherche, et n'est jamais
	// partagée. Elle devrait l'être si on se mettait un jour à la garder d'une
	// recherche à l'autre.
	decisions map[string]bool
}

// NouvellePortee construit la portée à partir de permissions déjà lues.
//
// Séparée de la lecture en base pour que la RÈGLE — ce qui est autorisé, et ce
// qui ne l'est pas — s'éprouve sans base de données. C'est le cœur du point 120,
// et il doit être testable directement.
func NouvellePortee(permissions []string) *PorteeDeRecherche {
	// Les permissions sont ANALYSÉES puis leurs domaines normalisés ; les domaines
	// interrogés le sont de la même façon. C'est le point important.
	//
	// `GetGroupsUnderDomain` compare les domaines après `NormaliserDomaine` — c'est
	// elle qui décide des groupes CHARGÉS. `permission.IsUserAuthorizedToSearch`,
	// lui, compare octet à octet. Ne normaliser qu'un côté ferait charger un groupe
	// dont `domain_name` vaut « Admin.Enov.Local », puis l'écarter au filtrage : un
	// compte qui voyait ce groupe avant le correctif ne le verrait plus, sans que
	// rien ne dise pourquoi.
	//
	// La normalisation porte sur les NOMS DE DOMAINE, jamais sur la chaîne de
	// permission entière. Mettre celle-ci en minuscules paraissait équivalent — sa
	// grammaire est faite de chiffres et de ponctuation — mais c'est faux : elle
	// porte aussi les mots-clés « all » et « nil », comparés littéralement par
	// `ParsePermissionAction`. Une valeur « ALL » écrite à la main en base était
	// lue comme un « custom » sans aucun domaine, donc REFUSÉE ; mise en
	// minuscules, elle serait devenue « tous les domaines ». Une normalisation ne
	// doit jamais pouvoir élargir un droit.
	actions := make([]storage.PermissionAction, 0, len(permissions))
	for _, brut := range permissions {
		pa := permission.ParsePermissionAction(brut)
		pa.WithPropagation = normaliserListe(pa.WithPropagation)
		pa.WithoutPropagation = normaliserListe(pa.WithoutPropagation)
		actions = append(actions, pa)
	}
	return &PorteeDeRecherche{
		actions:   actions,
		decisions: make(map[string]bool, 8),
	}
}

func normaliserListe(domaines []string) []string {
	if len(domaines) == 0 {
		return nil
	}
	out := make([]string, 0, len(domaines))
	for _, d := range domaines {
		if n := domainpkg.NormaliserDomaine(d); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// PorteeDeRecherchePour lit les permissions « search » d'un compte.
//
// Une erreur de lecture rend une portée VIDE et non nil : une base en difficulté
// doit refuser, pas ouvrir. L'appelant reçoit l'erreur et décide de la réponse
// LDAP, mais même s'il l'ignorait, la portée rendue n'autorise rien.
func PorteeDeRecherchePour(username string) (*PorteeDeRecherche, error) {
	// Nom vide : c'est la valeur que porte une session anonyme. Interroger le
	// RBAC avec elle ne rendrait probablement rien, mais « probablement » n'est
	// pas une garantie : il suffirait d'une jointure permissive pour que
	// l'anonyme hérite de droits.
	//
	// Le dispatcheur interdit déjà à un anonyme toute recherche autre que
	// RootDSE. Ce contrôle-ci est le second verrou, local à la décision.
	if strings.TrimSpace(username) == "" {
		return NouvellePortee(nil), fmt.Errorf("recherche sans compte lié")
	}

	perms, err := dbpermission.GetUserPermissionsForAction(
		database.GetDatabase(),
		username,
		"search",
	)
	if err != nil {
		return NouvellePortee(nil), err
	}
	return NouvellePortee(perms), nil
}

// Autorise dit si le compte a le droit de lire un domaine donné.
func (p *PorteeDeRecherche) Autorise(domaine string) bool {
	if p == nil {
		return false
	}

	domaine = normaliserDomaine(domaine)

	// Domaine inconnu : REFUS.
	//
	// C'est ce que rend une entrée qui n'appartient à aucun domaine (RootDSE,
	// sous-schéma) — servies par un chemin qui ne passe pas ici — et ce que
	// rendrait un futur type d'entrée dont on aurait oublié de renseigner le
	// domaine. Dans les deux cas, écarter est le comportement sûr : un oubli
	// rend l'entrée invisible, il ne la diffuse pas.
	if domaine == "" {
		return false
	}

	if décision, connu := p.decisions[domaine]; connu {
		return décision
	}
	décision := p.decider(domaine)
	p.decisions[domaine] = décision
	return décision
}

// decider applique la règle, sur des domaines déjà normalisés des deux côtés.
//
// C'est la règle de `permission.IsUserAuthorizedToSearch`, réécrite ici pour une
// seule raison : celle-là prend des permissions BRUTES et les analyse elle-même,
// donc elle ne peut pas comparer des domaines normalisés. Les deux doivent rendre
// le même verdict sur des entrées déjà en minuscules, et un test le vérifie cas
// par cas — voir portee_test.go.
func (p *PorteeDeRecherche) decider(domaine string) bool {
	for _, pa := range p.actions {
		switch pa.Type {
		case "all":
			return true
		case "custom":
			for _, d := range pa.WithPropagation {
				// Avec propagation : le domaine lui-même et ses sous-domaines. Le point
				// est dans le motif — sans lui, « faux-enov.local » passerait pour un
				// sous-domaine de « enov.local ».
				if domaine == d || strings.HasSuffix(domaine, "."+d) {
					return true
				}
			}
			for _, d := range pa.WithoutPropagation {
				if domaine == d {
					return true
				}
			}
		}
	}
	return false
}

// normaliserDomaine met un nom de domaine sous la forme employée pour comparer.
//
// Délègue à `domain.NormaliserDomaine`, qui décide des groupes CHARGÉS, au lieu
// d'en recopier le contenu : deux normalisations qui se ressemblent finissent par
// diverger, et la divergence se manifeste en entrée chargée puis écartée — donc
// en compte qui disparaît sans raison lisible.
func normaliserDomaine(domaine string) string {
	return domainpkg.NormaliserDomaine(domaine)
}

// AutoriseUnDes dit si AU MOINS un des rattachements d'une entrée est autorisé.
//
// « Au moins un », parce qu'un compte appartient à des groupes qui peuvent vivre
// dans des domaines différents : un compte membre d'un groupe de `enov.local` et
// d'un groupe de `admin.enov.local` est légitimement visible d'un délégué de
// `enov.local`, y compris sans propagation.
//
// Une liste VIDE est refusée. C'est ce que rendent le RootDSE et le sous-schéma —
// servis par un chemin qui ne passe pas par ici — et ce que rendrait une entrée
// construite sans renseigner ses rattachements. L'oubli rend l'entrée invisible,
// il ne la diffuse pas.
func (p *PorteeDeRecherche) AutoriseUnDes(domaines []string) bool {
	if p == nil {
		return false
	}
	for _, d := range domaines {
		if p.Autorise(d) {
			return true
		}
	}
	return false
}

// Filtrer retient les entrées dont au moins un rattachement est autorisé.
//
// Rend aussi le nombre d'entrées écartées : c'est ce qui permet de distinguer,
// dans le journal, une recherche qui ne trouve rien d'une recherche dont le
// résultat a été réduit par les droits — deux causes que le client voit de la
// même façon, puisqu'il reçoit dans les deux cas un succès et zéro entrée.
func (p *PorteeDeRecherche) Filtrer(entrées []ldapinterface.LDAPEntry) (retenues []ldapinterface.LDAPEntry, écartées int) {
	if p == nil {
		return nil, len(entrées)
	}

	retenues = make([]ldapinterface.LDAPEntry, 0, len(entrées))
	for _, e := range entrées {
		if p.AutoriseUnDes(e.Domaines()) {
			retenues = append(retenues, e)
			continue
		}
		écartées++
		logs.Write_Log("DEBUG", fmt.Sprintf(
			"ldap: entrée écartée par les droits : %s (rattachements %v)", e.DN(), e.Domaines()))
	}
	return retenues, écartées
}
