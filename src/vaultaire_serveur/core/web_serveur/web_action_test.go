package webserveur

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"vaultaire/core/action"
)

// cheminGabarits localise les gabarits depuis le répertoire du paquet.
//
// Chemin relatif et non adminTplDir : cette constante vaut un chemin
// d'exécution du serveur, alors qu'un test tourne dans le répertoire de son
// paquet. Employer la constante ferait échouer le test partout sauf sur une
// machine où le serveur est installé.
const cheminGabarits = "../../../../cmd/web_packet/sso_WEB_page/templates"

// --- La garantie architecturale ---------------------------------------------
//
// L'exigence est : plus aucune action déclenchée depuis le web sans passer par
// le registre.
//
// Remplacer le code ne suffit pas à la tenir. Rien n'empêcherait un handler
// écrit demain d'appeler à nouveau la base directement — et ce serait
// invisible, puisque cela compilerait, fonctionnerait, et ne réapparaîtrait
// dans aucun test.
//
// Le test ci-dessous lit les sources et refuse les appels d'ÉCRITURE en base
// depuis le paquet web. C'est une contrainte de structure, vérifiée
// mécaniquement plutôt que confiée à la vigilance.

// ecrituresEnBase reconnaît les fonctions de la couche de persistance qui
// MODIFIENT quelque chose.
//
// La lecture reste permise : les pages affichent des listes, et les faire
// transiter par le registre n'apporterait rien — une lecture n'a pas d'effet à
// contrôler, et son résultat sert directement au gabarit.
//
// Ce qui est traqué est l'écriture, parce que c'est elle qui porte une décision
// et donc un contrôle de droits.
var ecrituresEnBase = regexp.MustCompile(
	`\bdb[a-z]+\.(Create|Command_ADD_|Command_DELETE_|Command_Remove_|Command_UPDATE_|` +
		`Update|Set[A-Z]|Link|Unlink|Delete|Revoke)[A-Za-z_]*\s*\(`)

// fichiersExemptes sont les fichiers où l'écriture directe reste tolérée, avec
// la raison.
//
// Chaque entrée est une dette nommée. Une exemption sans justification écrite
// serait indiscernable d'un oubli — et c'est exactement ainsi que les
// exceptions se multiplient.
var fichiersExemptes = map[string]string{
	// Les GPO ont été explicitement exclus du périmètre de la refonte : leur
	// logique est spécifique et ne se plie pas au modèle « une action, des
	// paramètres nommés ».
	"web_admin_gpo.go":              "GPO hors périmètre, exclu par décision",
	"web_admin_gpo_restrictions.go": "GPO hors périmètre, exclu par décision",

	// Les sessions et le second facteur de l'utilisateur COURANT ne sont pas
	// des actions d'administration : elles ne visent pas un tiers, ne relèvent
	// d'aucune délégation, et leur contrôle est l'authentification elle-même.
	"web_profil.go":     "l'utilisateur agit sur son propre compte",
	"web_profil_mfa.go": "l'utilisateur agit sur son propre second facteur",
	"web_login.go":      "authentification, antérieure à toute autorisation",
	"web_login_mfa.go":  "authentification, antérieure à toute autorisation",
}

// TestAucuneEcritureDirecteEnBaseDepuisLeWeb.
//
// Le test qui tient l'exigence. Il échoue sur tout appel d'écriture non exempté,
// en nommant le fichier, la ligne et l'appel.
func TestAucuneEcritureDirecteEnBaseDepuisLeWeb(t *testing.T) {
	fichiers, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("lecture du répertoire : %v", err)
	}
	if len(fichiers) == 0 {
		t.Fatal("aucun fichier source trouvé : le test ne vérifie rien")
	}

	var infractions []string
	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		if _, exempte := fichiersExemptes[filepath.Base(f)]; exempte {
			continue
		}

		contenu, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("lecture de %s : %v", f, err)
		}
		for i, ligne := range strings.Split(string(contenu), "\n") {
			// Les commentaires citent souvent le code d'avant pour expliquer ce
			// qui a changé. Les compter comme des infractions rendrait
			// impossible d'écrire cette explication.
			nettoyee := strings.TrimSpace(ligne)
			if strings.HasPrefix(nettoyee, "//") {
				continue
			}
			if m := ecrituresEnBase.FindString(ligne); m != "" {
				infractions = append(infractions,
					filepath.Base(f)+":"+itoa(i+1)+" — "+strings.TrimSuffix(m, "("))
			}
		}
	}

	if len(infractions) > 0 {
		sort.Strings(infractions)
		t.Fatalf(
			"%d écriture(s) en base depuis le serveur web sans passer par le registre :\n  %s\n\n"+
				"Une écriture directe échappe au contrôle des droits porté par l'action, "+
				"et recrée la logique en double avec la ligne de commande. "+
				"Passez par action.Executer, ou ajoutez le fichier à fichiersExemptes "+
				"AVEC la raison.",
			len(infractions), strings.Join(infractions, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var chiffres []byte
	for n > 0 {
		chiffres = append([]byte{byte('0' + n%10)}, chiffres...)
		n /= 10
	}
	return string(chiffres)
}

// TestExemptionsToutesJustifiees : une exemption vide serait un oubli déguisé.
func TestExemptionsToutesJustifiees(t *testing.T) {
	for fichier, raison := range fichiersExemptes {
		if strings.TrimSpace(raison) == "" {
			t.Errorf("exemption de %q sans raison écrite", fichier)
		}
		if _, err := os.Stat(fichier); os.IsNotExist(err) {
			// Une exemption qui ne correspond plus à aucun fichier laisse
			// croire qu'une dette subsiste alors qu'elle est réglée — ou
			// masque un renommage qui a fait sortir du contrôle.
			t.Errorf("exemption de %q : ce fichier n'existe pas", fichier)
		}
	}
}

// --- La table de correspondance ---------------------------------------------

// TestToutesLesActionsDeFormulaireExistentAuRegistre.
//
// Une entrée qui pointe vers une action inexistante produirait un refus à
// l'exécution, découvert par l'utilisateur au moment où il clique. Le test le
// découvre avant.
func TestToutesLesActionsDeFormulaireExistentAuRegistre(t *testing.T) {
	action.EnregistrerTout()

	for _, nomFormulaire := range ActionsDeFormulaireConnues() {
		nomAction, _ := ActionDuRegistrePour(nomFormulaire)
		if _, existe := action.Catalogue.Definition(nomAction); !existe {
			t.Errorf("le formulaire %q désigne l'action %q, absente du registre",
				nomFormulaire, nomAction)
		}
	}
}

// TestToutesLesActionsDesGabaritsSontRoutees.
//
// # Le défaut que ce test a trouvé
//
// Quatre actions figuraient dans les gabarits sans être dans la table du pont :
// add_group, remove_group, delete_user et reset_mfa. Elles auraient été refusées
// avec « action de formulaire inconnue » — alors que les actions correspondantes
// existent bel et bien au registre.
//
// Le cas d'add_group est instructif : le MÊME lien porte deux noms selon la page
// qui l'expose. « add_user » depuis la fiche d'un groupe, « add_group » depuis
// celle d'un utilisateur. La lecture du code seul ne le montre pas — il faut
// croiser les gabarits avec la table.
//
// # Les exemptions
//
// Les actions hors périmètre — GPO, cluster, profil de l'utilisateur courant —
// sont listées explicitement. Une liste plutôt qu'un filtre sur le nom : un
// filtre laisserait passer une action réellement oubliée dont le nom
// ressemblerait à celles qu'on écarte.
func TestToutesLesActionsDesGabaritsSontRoutees(t *testing.T) {
	horsPerimetre := map[string]string{
		// GPO — exclues de la refonte par décision.
		"create_gpo": "GPO", "update_gpo": "GPO", "delete_gpo": "GPO",
		"add_module": "GPO", "update_module": "GPO", "delete_module": "GPO",
		"add_path": "GPO", "add_env": "GPO", "add_value": "GPO",
		"save_definition": "GPO", "delete_definition": "GPO",
		"delete_restriction": "GPO", "set_rule": "GPO", "reset_defaults": "GPO",
		"link_group": "GPO", "unlink_group": "GPO",

		// Grammaire interne des permissions RBAC — voir web_admin_pages.go.
		"update_permission_action": "grammaire RBAC, hors périmètre",

		// Profil de l'utilisateur courant : ne vise pas un tiers.
		"add_key": "profil", "delete_key": "profil", "update_info": "profil",
		"confirm": "profil", "disable": "profil", "start": "profil",

		// Kill switch : sa logique — modes, confirmation par ressaisie — vit
		// dans le handler, et ses contrôles dans revocationmanager.Trigger.
		"kill_user": "kill switch",

		// Réglage du serveur, pas une entité de l'annuaire.
		"set_debug": "réglage serveur",
	}

	gabarits, err := actionsDesGabarits()
	if err != nil {
		t.Fatalf("lecture des gabarits : %v", err)
	}
	if len(gabarits) == 0 {
		t.Fatal("aucune action trouvée dans les gabarits : le test ne vérifie rien")
	}

	var manquantes []string
	for _, nom := range gabarits {
		if _, routee := ActionDuRegistrePour(nom); routee {
			continue
		}
		if _, exempte := horsPerimetre[nom]; exempte {
			continue
		}
		manquantes = append(manquantes, nom)
	}

	if len(manquantes) > 0 {
		sort.Strings(manquantes)
		t.Fatalf(
			"%d action(s) de formulaire ne sont routées vers aucune action du registre :\n  %s\n\n"+
				"Elles seront refusées avec « action de formulaire inconnue ». "+
				"Ajoutez-les à actionsFormulaire, ou à horsPerimetre AVEC leur raison.",
			len(manquantes), strings.Join(manquantes, "\n  "))
	}
}

// actionsDesGabarits relève les valeurs du champ « action » dans les gabarits.
func actionsDesGabarits() ([]string, error) {
	fichiers, err := filepath.Glob(cheminGabarits + "/*.html")
	if err != nil {
		return nil, err
	}
	motif := regexp.MustCompile(`name="action"\s+value="([a-z_]+)"`)
	vues := map[string]bool{}
	var out []string
	for _, f := range fichiers {
		contenu, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, m := range motif.FindAllStringSubmatch(string(contenu), -1) {
			if !vues[m[1]] {
				vues[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// TestPontSansEntreeMorte : l'inverse du test précédent.
//
// Une entrée de la table qu'aucun gabarit n'emploie est soit un reste d'un
// formulaire supprimé, soit une faute de frappe qui masque l'absence de la
// vraie. Dans les deux cas, elle laisse croire qu'une action est routée alors
// que rien ne la déclenche.
func TestPontSansEntreeMorte(t *testing.T) {
	gabarits, err := actionsDesGabarits()
	if err != nil {
		t.Fatalf("lecture des gabarits : %v", err)
	}
	presentes := map[string]bool{}
	for _, g := range gabarits {
		presentes[g] = true
	}

	var mortes []string
	for _, nom := range ActionsDeFormulaireConnues() {
		if !presentes[nom] {
			mortes = append(mortes, nom)
		}
	}
	if len(mortes) > 0 {
		sort.Strings(mortes)
		t.Errorf("%d entrée(s) du pont qu'aucun gabarit n'emploie :\n  %s\n\n"+
			"Reste d'un formulaire supprimé, ou faute de frappe qui masque l'absence de la vraie.",
			len(mortes), strings.Join(mortes, "\n  "))
	}
}

// TestActionInconnueEstRefusee est le renversement du fail-open.
//
// Dans l'ancien code, un nom absent de la table laissait la clé RBAC vide et
// l'action s'exécutait sans contrôle. Ici l'inconnu est refusé.
func TestActionInconnueEstRefusee(t *testing.T) {
	if _, connue := ActionDuRegistrePour("action_inventee_qui_nexiste_pas"); connue {
		t.Fatal("une action inventée est reconnue")
	}
}

// TestAliasNecraseParUneValeurExplicite.
//
// Les gabarits emploient « target_group » ici, « group » là. L'alias comble
// l'absence, il ne doit pas écraser : un formulaire qui envoie les deux, avec
// des valeurs différentes, viserait sinon le mauvais groupe.
func TestAliasNecrasePasUneValeurExplicite(t *testing.T) {
	p := action.Params{"group": "paris", "target_group": "lyon"}

	// Reproduction de la règle d'application des alias.
	for source, canonique := range aliasParametres {
		if _, deja := p[canonique]; deja {
			continue
		}
		if v, present := p[source]; present {
			p[canonique] = v
		}
	}

	if p["group"] != "paris" {
		t.Fatalf("group vaut %q : l'alias a écrasé une valeur explicite, "+
			"l'action viserait le mauvais groupe", p["group"])
	}
}

func TestAliasCompleteUneValeurAbsente(t *testing.T) {
	p := action.Params{"target_group": "lyon"}
	for source, canonique := range aliasParametres {
		if _, deja := p[canonique]; deja {
			continue
		}
		if v, present := p[source]; present {
			p[canonique] = v
		}
	}
	if p["group"] != "lyon" {
		t.Fatalf("group vaut %q, attendu lyon : les formulaires employant "+
			"« target_group » ne fonctionneraient pas", p["group"])
	}
}
