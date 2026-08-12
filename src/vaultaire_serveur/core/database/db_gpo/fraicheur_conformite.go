package dbgpo

import (
	"database/sql"
	"sort"
	"time"
)

// Fraîcheur d'un rapport de conformité, et ordre d'affichage du parc.
//
// # Pourquoi ce fichier n'interroge aucune base
//
// Ce qu'il décide — « cette machine est-elle en retard ? », « laquelle montrer
// en premier ? » — est du raisonnement, pas de la lecture. L'écrire en SQL le
// rendrait dépendant de l'horloge du serveur de base, et surtout intestable
// sans base : personne ne vérifierait jamais l'ordre, qui est pourtant la seule
// chose sur laquelle un administrateur s'appuie quand la liste dépasse l'écran.
//
// Tout est donc pur : des lignes en entrée, un instant en paramètre.

// IntervalleRapportAgent est la cadence à laquelle un agent rapporte.
//
// ATTENTION : cette valeur DUPLIQUE gpo.MachineRefreshInterval de
// vaultaire_client. Les deux vivent dans des modules Go distincts — le serveur
// n'importe pas l'agent — et rien ne peut donc les tenir liées à la
// compilation.
//
// Les faire diverger n'a pas d'effet visible immédiat, ce qui est le pire des
// cas : allonger la cadence de l'agent sans toucher à celle-ci ferait
// apparaître tout le parc « en retard » du jour au lendemain, et on
// conclurait à une panne.
const IntervalleRapportAgent = 1 * time.Hour

// ToleranceRapport est le délai au-delà duquel un silence devient un retard.
//
// TROIS cycles, et non un. Un redémarrage, une coupure réseau brève, une
// fenêtre de maintenance, un agent relancé après mise à jour : chacun coûte un
// cycle manqué et aucun n'est un incident. Signaler dès le premier remplirait
// la vue de retards qui se résolvent seuls, et l'administrateur cesserait de la
// lire — ce qui reviendrait à n'avoir rien signalé du tout.
const ToleranceRapport = 3 * IntervalleRapportAgent

// ScopeInconnu remplace le scope d'une machine qui n'a jamais rapporté.
//
// La colonne est vide dans ce cas, et afficher une case vide laisserait croire
// à une donnée manquante plutôt qu'à un fait : on ne sait pas ce que cette
// machine applique, parce qu'elle ne l'a jamais dit.
const ScopeInconnu = "?"

// NormaliserLigne achève une ligne à partir de ce que la base a rendu.
//
// Séparée du scan SQL, et exportée, pour UNE raison : la décision qu'elle porte
// — « pas de date de rapport signifie machine muette » — est la conclusion de
// toute la LEFT JOIN. Laissée au milieu d'une boucle rows.Next(), elle ne
// s'éprouve qu'avec une base, c'est-à-dire jamais dans le harnais hors ligne.
//
// Une mutation l'a montré : remplacer ScopeInconnu par une chaîne vide ne
// faisait échouer aucun test, parce que les tests fabriquaient leurs lignes à
// la main en recopiant la constante. Ils vérifiaient la constante contre
// elle-même.
func NormaliserLigne(r ComplianceRow, rapporteA sql.NullTime) ComplianceRow {
	if rapporteA.Valid {
		r.ReportedAt = rapporteA.Time
		return r
	}
	r.JamaisRapporte = true
	// La portée est vide sur ces lignes — la LEFT JOIN n'a rien trouvé à
	// joindre. Une case vide se lit comme une donnée manquante ; « ? » se lit
	// comme un fait : on ne sait pas ce que cette machine applique, parce
	// qu'elle ne l'a jamais dit.
	r.Scope = ScopeInconnu
	return r
}

// EtatRapport qualifie la fraîcheur d'un rapport.
type EtatRapport string

const (
	// RapportAJour : la machine a rapporté dans la fenêtre attendue.
	RapportAJour EtatRapport = "à jour"
	// RapportEnRetard : elle a rapporté un jour, plus depuis ToleranceRapport.
	RapportEnRetard EtatRapport = "en retard"
	// RapportJamais : elle est à l'inventaire et n'a jamais rapporté.
	RapportJamais EtatRapport = "jamais"
)

// Fraicheur qualifie la ligne à un instant donné.
//
// `maintenant` est un paramètre et non time.Now() : un test qui devrait
// attendre trois heures pour éprouver le retard ne serait jamais écrit.
func (r ComplianceRow) Fraicheur(maintenant time.Time) EtatRapport {
	if r.JamaisRapporte || r.ReportedAt.IsZero() {
		return RapportJamais
	}
	if maintenant.Sub(r.ReportedAt.UTC()) > ToleranceRapport {
		return RapportEnRetard
	}
	return RapportAJour
}

// Silencieuse : la machine ne dit plus ce qu'elle applique.
//
// Regroupe « jamais » et « en retard » sous la question qui compte vraiment —
// est-ce que je sais dans quel état est cette machine ? Non, dans les deux cas.
func (r ComplianceRow) Silencieuse(maintenant time.Time) bool {
	return r.Fraicheur(maintenant) != RapportAJour
}

// TrierConformite place devant ce dont on ne sait rien, puis ce qui va mal.
//
// # L'ordre, et pourquoi celui-là
//
//  1. le SILENCE — jamais rapporté, ou en retard ;
//  2. les modules en ÉCHEC ;
//  3. les ÉCARTS de conformité, du plus grand nombre au plus petit ;
//  4. le reste, par identifiant puis portée, pour que deux exécutions
//     successives rendent le même tableau.
//
// Le silence passe AVANT l'échec, ce qui peut surprendre : un échec est un
// problème avéré, un silence n'est peut-être rien. C'est justement la raison.
// Un échec est visible et chiffré — on sait quoi corriger. Un silence ne dit
// rien du tout : la machine peut être éteinte, ou bien avoir dérivé depuis
// trois semaines sans que personne ne l'apprenne. L'inconnu se traite avant le
// connu, sinon il ne se traite jamais.
//
// # D'où vient le déterminisme
//
// De la chaîne de départage, qui va jusqu'à l'utilisateur cible — pas de
// SliceStable. C'est ce qu'une mutation a montré : remplacer SliceStable par
// Slice ne change RIEN au résultat, parce que deux lignes ne peuvent pas être
// égales sur tous les critères. La clé UNIQUE de gpo_compliance porte
// exactement ce triplet.
//
// SliceStable est conservé quand même, pour le jour où un critère disparaîtrait
// de la chaîne : le tri resterait alors reproductible au lieu de se mettre à
// varier d'une exécution à l'autre sur des données identiques, ce qui est le
// genre de défaut qu'on met des semaines à imputer au tri.
func TrierConformite(rows []ComplianceRow, maintenant time.Time) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]

		if sa, sb := a.Silencieuse(maintenant), b.Silencieuse(maintenant); sa != sb {
			return sa
		}
		if ea, eb := a.ModulesFailed > 0, b.ModulesFailed > 0; ea != eb {
			return ea
		}
		if a.DriftCount != b.DriftCount {
			return a.DriftCount > b.DriftCount
		}
		if a.ComputeurID != b.ComputeurID {
			return a.ComputeurID < b.ComputeurID
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return a.TargetUser < b.TargetUser
	})
}

// ResumeParc compte ce qu'un administrateur veut lire en une ligne.
type ResumeParc struct {
	Machines   int // machines distinctes à l'inventaire
	Jamais     int // n'ont jamais rapporté
	EnRetard   int // ont rapporté un jour, plus depuis ToleranceRapport
	EnEchec    int // au moins un module en échec
	AvecEcarts int // au moins un écart de conformité constaté
}

// ResumerParc agrège les lignes en un état d'ensemble.
//
// Les compteurs portent sur les MACHINES et non sur les lignes : une machine
// dont deux portées sont en échec est un problème, pas deux. Compter les lignes
// gonflerait les chiffres à proportion du nombre d'utilisateurs connectés, et
// « 47 échecs » sur un parc de 12 machines ne veut rien dire.
func ResumerParc(rows []ComplianceRow, maintenant time.Time) ResumeParc {
	var out ResumeParc
	vues := map[string]bool{}
	jamais := map[string]bool{}
	retard := map[string]bool{}
	echec := map[string]bool{}
	ecarts := map[string]bool{}

	for _, r := range rows {
		if !vues[r.ComputeurID] {
			vues[r.ComputeurID] = true
			out.Machines++
		}
		switch r.Fraicheur(maintenant) {
		case RapportJamais:
			if !jamais[r.ComputeurID] {
				jamais[r.ComputeurID] = true
				out.Jamais++
			}
		case RapportEnRetard:
			if !retard[r.ComputeurID] {
				retard[r.ComputeurID] = true
				out.EnRetard++
			}
		}
		if r.ModulesFailed > 0 && !echec[r.ComputeurID] {
			echec[r.ComputeurID] = true
			out.EnEchec++
		}
		if r.DriftCount > 0 && !ecarts[r.ComputeurID] {
			ecarts[r.ComputeurID] = true
			out.AvecEcarts++
		}
	}
	return out
}
