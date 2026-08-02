package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Primitives de transport des politiques vers les agents clients.
//
// Voir docs/Developement/Tableau_Protocole_Réseau.md, section « Détail du
// transport GPO » : catégorie de trames 05_01 à 05_14, modèle pull, manifeste
// suivi de fragments.
//
// Deux empreintes distinctes cohabitent ici, et les confondre serait une source
// de bugs difficiles :
//
//   - l'empreinte de POLITIQUE (PolicyHash, forme canonique) identifie la
//     configuration voulue. C'est elle qui sert à décider s'il y a quelque chose
//     à appliquer, et elle ne dépend pas du format de livraison ;
//   - la somme de contrôle de CHARGE (PayloadChecksum) porte sur les octets
//     réellement transmis. Elle ne sert qu'à valider le réassemblage des
//     fragments côté client.

// ChunkSize est la taille d'un fragment de politique, en octets de texte clair.
//
// La couche de transport annonce la taille du message sur 2 octets et chiffre en
// AES-GCM avant encodage base64, ce qui plafonne une trame à environ 49 000
// octets utiles. 32 Kio laisse une marge confortable pour l'en-tête de trame
// sans multiplier les allers-retours.
const ChunkSize = 32 * 1024

// DeliveryDefinition est le contenu d'une valeur nommée, transmis avec le module
// qui la référence.
//
// Sans elle, l'agent ne recevrait que le NOM du jeu de commandes et devrait en
// connaître le contenu localement : créer un jeu custom depuis l'interface
// n'aurait alors aucun effet sur le parc, ce qui vide le mécanisme de son sens.
type DeliveryDefinition struct {
	Name    string      `json:"name"`
	Kind    PayloadKind `json:"kind"`
	Payload string      `json:"payload"`
}

// DeliveryModule est un module tel que transmis à l'agent.
//
// StateKey et Fingerprint sont calculés par le serveur et transmis, plutôt que
// recalculés par l'agent : le client est un module Go séparé, deux
// implémentations du même hachage finiraient par diverger et la détection de
// changement deviendrait silencieusement fausse.
type DeliveryModule struct {
	Type        string            `json:"type"`
	Scope       Scope             `json:"scope"`
	ApplyOrder  int               `json:"apply_order"`
	Params      map[string]string `json:"params"`
	StateKey    string            `json:"state_key"`
	Fingerprint string            `json:"fingerprint"`
	// Definitions porte le contenu des valeurs nommées référencées par les
	// paramètres, indexé par nom de champ.
	Definitions map[string]DeliveryDefinition `json:"definitions,omitempty"`
}

// ResolveModuleDefinitions retourne le contenu des définitions référencées par
// un module, indexé par nom de champ.
//
// Seuls les champs déclarés porteurs de contenu (voir PayloadKindFor) sont
// résolus. Une valeur sans définition correspondante retourne une entrée vide :
// c'est un défaut de configuration côté serveur, et il vaut mieux que l'agent le
// rapporte explicitement que de recevoir un module amputé sans le savoir.
func ResolveModuleDefinitions(m Module) map[string]DeliveryDefinition {
	schema, ok := BaseSchemaFor(m.Type)
	if !ok {
		return nil
	}

	var out map[string]DeliveryDefinition
	for _, f := range schema.Fields {
		kind := PayloadKindFor(m.Type, f.Name)
		if kind == PayloadNone {
			continue
		}
		value := strings.TrimSpace(m.Params[f.Name])
		if value == "" {
			continue
		}
		if out == nil {
			out = map[string]DeliveryDefinition{}
		}
		definition, found := Restrictions().Definition(m.Type, f.Name, value)
		if !found {
			out[f.Name] = DeliveryDefinition{Name: value, Kind: kind}
			continue
		}
		out[f.Name] = DeliveryDefinition{
			Name: definition.Name, Kind: kind, Payload: definition.Payload,
		}
	}
	return out
}

// definitionsForHash aplatit les définitions d'un module pour le hachage.
//
// Le contenu des définitions DOIT entrer dans les empreintes : sans cela,
// modifier la liste de commandes d'un jeu sudo ne changerait ni l'empreinte du
// module ni celle de la politique, et le parc conserverait indéfiniment
// l'ancienne règle en se croyant à jour.
func definitionsForHash(m Module) map[string]string {
	resolved := ResolveModuleDefinitions(m)
	if len(resolved) == 0 {
		return nil
	}
	out := make(map[string]string, len(resolved))
	for field, definition := range resolved {
		out[field] = string(definition.Kind) + "\x00" + definition.Name + "\x00" + definition.Payload
	}
	return out
}

// DeliveryPolicy est la politique effective telle que transmise à l'agent.
type DeliveryPolicy struct {
	Name        string           `json:"name"`
	Scope       Scope            `json:"scope"`
	Username    string           `json:"username,omitempty"`
	Version     int              `json:"version"`
	Fingerprint string           `json:"fingerprint"`
	Modules     []DeliveryModule `json:"modules"`
	// Signature est réservée : la politique n'est pas encore signée. Le tunnel
	// Ducky couvre l'écoute et l'altération en transit, pas un serveur central
	// compromis. Le champ existe pour ne pas avoir à changer les trames plus tard.
	Signature string `json:"signature,omitempty"`
}

// ModuleStateKey retourne l'identité stable d'un module, sous une forme
// exploitable comme clé dans l'état local de l'agent.
//
// Distincte de moduleIdentity, qui produit une phrase destinée aux messages
// d'erreur. Ici on veut une clé courte, stable et sans espace, du type
// « sysctl:net.ipv4.ip_forward ».
func ModuleStateKey(m Module) string {
	suffix := ""
	switch m.Type {
	case ModuleSysctl:
		suffix = m.Params["key"]
	case ModuleSystemdService:
		suffix = m.Params["service"]
	case ModulePackage:
		suffix = m.Params["package"]
	case ModuleFileDeploy:
		suffix = m.Params["path"]
	case ModuleUserEnv:
		suffix = strings.ToUpper(m.Params["name"])
	case ModuleUserCron:
		suffix = m.Params["command_id"]
	case ModuleSudoersRule:
		suffix = m.Params["group"]
	case ModuleDirectoryManage:
		suffix = m.Params["path"]
	case ModuleTemplatedFile:
		suffix = m.Params["path"]
	case ModuleTrustedCA:
		suffix = m.Params["name"]
	case ModulePackageRepo:
		suffix = m.Params["name"]
	case ModuleFirewallRule:
		// Un port seul ne suffit pas : 443/tcp et 443/udp sont deux règles
		// distinctes, et les confondre ferait que la seconde écraserait l'état
		// de la première dans le suivi de l'agent.
		suffix = m.Params["port"] + "/" + m.Params["protocol"]
	case ModuleDNSResolver:
		// Un seul jeu de résolveurs par machine : deux modules qui se
		// contrediraient sont un conflit, pas deux réglages coexistants.
		suffix = "-"
	case ModuleFileACL:
		// Un chemin peut porter plusieurs ACL, une par bénéficiaire : la clé les
		// distingue, sans quoi la seconde écraserait l'état de la première.
		suffix = m.Params["path"] + "#" + m.Params["kind"] + ":" + m.Params["target"]
	case ModuleBootParams:
		suffix = m.Params["parameter"]
	case ModuleKernelModulePolicy:
		suffix = m.Params["module"]
	case ModuleSSHKnownHosts:
		suffix = m.Params["host"]
	case ModuleAuditdRule:
		suffix = m.Params["path"]
	case ModuleNTPConfig, ModuleLogPolicy, ModuleUpdatePolicy, ModulePAMPolicy,
		ModuleLocalAccountPolicy, ModuleSELinuxMode:
		// Réglages uniques par machine : deux modules qui se contrediraient sont
		// un conflit à signaler, pas deux réglages qui coexistent.
		suffix = "-"
	case ModuleSystemEnv:
		suffix = strings.ToUpper(m.Params["name"])
	case ModuleResourceLimits:
		suffix = m.Params["domain"] + ":" + m.Params["limit_type"] + ":" + m.Params["item"]
	case ModuleFileRetention:
		suffix = m.Params["directory"] + "#" + m.Params["pattern"]
	case ModuleUserGroupMembership:
		suffix = m.Params["group"]
	case ModuleUserSSHClientConfig:
		suffix = m.Params["host_alias"]
	case ModuleUserGitConfig:
		suffix = m.Params["key"]
	case ModuleUserShell, ModuleUserPasswordPolicy, ModuleUserResourceLimits:
		// Un seul par utilisateur.
		suffix = "-"
	case ModuleSSHServerConfig:
		// Un seul module SSH par politique (clé naturelle unique) : pas de suffixe.
		suffix = "-"
	default:
		suffix = "-"
	}
	if strings.TrimSpace(suffix) == "" {
		suffix = "-"
	}
	return m.Type + ":" + suffix
}

// ModuleFingerprint retourne l'empreinte d'un module : type, scope et paramètres.
//
// L'ordre d'application n'entre PAS dans l'empreinte. Réordonner le catalogue ne
// change rien à ce qui est appliqué sur la machine ; l'inclure provoquerait une
// réapplication inutile de tous les modules après une simple modification de code.
func ModuleFingerprint(m Module) (string, error) {
	type canonical struct {
		Type        string            `json:"type"`
		Scope       Scope             `json:"scope"`
		Params      map[string]string `json:"params"`
		Definitions map[string]string `json:"definitions,omitempty"`
	}
	data, err := json.Marshal(canonical{
		Type: m.Type, Scope: m.Scope, Params: m.Params, Definitions: definitionsForHash(m),
	})
	if err != nil {
		return "", fmt.Errorf("empreinte de module impossible : %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// BuildDeliveryPolicy construit le document de livraison d'une politique.
//
// L'empreinte de politique reste celle de la forme canonique : elle ne dépend pas
// des champs ajoutés pour la livraison, donc ajouter un champ de transport ne
// provoque pas une réapplication sur tout le parc.
func BuildDeliveryPolicy(p Policy, username string) (DeliveryPolicy, error) {
	fingerprint, err := PolicyHash(p)
	if err != nil {
		return DeliveryPolicy{}, err
	}

	modules := append([]Module(nil), p.Modules...)
	SortModules(modules)

	out := DeliveryPolicy{
		Name:        p.Name,
		Scope:       p.Scope,
		Username:    username,
		Version:     p.Version,
		Fingerprint: fingerprint,
	}
	for _, m := range modules {
		moduleFP, err := ModuleFingerprint(m)
		if err != nil {
			return DeliveryPolicy{}, err
		}
		out.Modules = append(out.Modules, DeliveryModule{
			Type:        m.Type,
			Scope:       m.Scope,
			ApplyOrder:  m.ApplyOrder,
			Params:      m.Params,
			StateKey:    ModuleStateKey(m),
			Fingerprint: moduleFP,
			Definitions: ResolveModuleDefinitions(m),
		})
	}
	return out, nil
}

// EncodeDeliveryPolicy sérialise la politique de livraison.
//
// Les clés de paramètres sont ordonnées par encoding/json (les maps sont
// sérialisées triées), donc la sortie est reproductible d'un envoi à l'autre.
func EncodeDeliveryPolicy(p DeliveryPolicy) ([]byte, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encodage de la politique de livraison impossible : %v", err)
	}
	return data, nil
}

// PayloadChecksum retourne la somme de contrôle des octets transmis.
// Sert uniquement à valider le réassemblage des fragments côté agent.
func PayloadChecksum(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// Manifest décrit une politique prête à être transférée.
type Manifest struct {
	Scope       Scope
	Username    string
	Version     int
	Fingerprint string
	Checksum    string
	TotalSize   int
	ChunkCount  int
	ModuleCount int
}

// Transfer est une politique sérialisée, découpée, prête à être servie fragment
// par fragment.
type Transfer struct {
	Manifest Manifest
	payload  []byte
}

// PrepareTransfer sérialise et découpe une politique effective.
func PrepareTransfer(p Policy, username string) (*Transfer, error) {
	delivery, err := BuildDeliveryPolicy(p, username)
	if err != nil {
		return nil, err
	}
	payload, err := EncodeDeliveryPolicy(delivery)
	if err != nil {
		return nil, err
	}

	chunkCount := len(payload) / ChunkSize
	if len(payload)%ChunkSize != 0 || chunkCount == 0 {
		chunkCount++
	}

	return &Transfer{
		Manifest: Manifest{
			Scope:       p.Scope,
			Username:    username,
			Version:     p.Version,
			Fingerprint: delivery.Fingerprint,
			Checksum:    PayloadChecksum(payload),
			TotalSize:   len(payload),
			ChunkCount:  chunkCount,
			ModuleCount: len(delivery.Modules),
		},
		payload: payload,
	}, nil
}

// Chunk retourne le fragment d'index donné.
func (t *Transfer) Chunk(index int) ([]byte, error) {
	if t == nil {
		return nil, fmt.Errorf("transfert inexistant")
	}
	if index < 0 || index >= t.Manifest.ChunkCount {
		return nil, fmt.Errorf("index de fragment %d hors bornes (0 à %d)", index, t.Manifest.ChunkCount-1)
	}
	start := index * ChunkSize
	end := start + ChunkSize
	if end > len(t.payload) {
		end = len(t.payload)
	}
	return t.payload[start:end], nil
}

// PayloadSize retourne la taille totale de la charge.
func (t *Transfer) PayloadSize() int {
	if t == nil {
		return 0
	}
	return len(t.payload)
}

// ApplyResult est le résultat d'application d'un module, tel que rapporté par
// l'agent (trame 05_12).
type ApplyResult string

const (
	ApplyResultApplied   ApplyResult = "applied"
	ApplyResultUnchanged ApplyResult = "unchanged"
	ApplyResultSkipped   ApplyResult = "skipped"
	ApplyResultFailed    ApplyResult = "failed"
)

// IsValidApplyResult indique si un résultat de module est reconnu.
func IsValidApplyResult(r string) bool {
	switch ApplyResult(r) {
	case ApplyResultApplied, ApplyResultUnchanged, ApplyResultSkipped, ApplyResultFailed:
		return true
	}
	return false
}

// ApplyStatus est le statut global d'une application.
type ApplyStatus string

const (
	ApplyStatusApplied ApplyStatus = "applied"
	ApplyStatusPartial ApplyStatus = "partial"
	ApplyStatusFailed  ApplyStatus = "failed"
)

// IsValidApplyStatus indique si un statut global est reconnu.
func IsValidApplyStatus(s string) bool {
	switch ApplyStatus(s) {
	case ApplyStatusApplied, ApplyStatusPartial, ApplyStatusFailed:
		return true
	}
	return false
}

// ModuleReport est la ligne de rapport d'un module.
type ModuleReport struct {
	ModuleType string
	StateKey   string
	Result     ApplyResult
	Detail     string
}

// ApplyReport est le rapport d'application complet remonté par un agent.
type ApplyReport struct {
	Scope       Scope
	Username    string
	Fingerprint string
	Status      ApplyStatus
	Modules     []ModuleReport
}

// FailedModules retourne les modules en échec, pour les messages de journal.
func (r ApplyReport) FailedModules() []ModuleReport {
	var out []ModuleReport
	for _, m := range r.Modules {
		if m.Result == ApplyResultFailed {
			out = append(out, m)
		}
	}
	return out
}

// Summary condense le rapport en une ligne de journal lisible.
func (r ApplyReport) Summary() string {
	counts := map[ApplyResult]int{}
	for _, m := range r.Modules {
		counts[m.Result]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[ApplyResult(k)]))
	}
	return fmt.Sprintf("statut=%s modules=%d (%s)", r.Status, len(r.Modules), strings.Join(parts, " "))
}
