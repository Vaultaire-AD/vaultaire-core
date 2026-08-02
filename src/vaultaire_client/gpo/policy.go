// Package gpo porte la réception, la comparaison et l'application des politiques
// GPO côté agent.
//
// Le client est un module Go distinct du serveur : il ne peut pas importer
// core/gpo. Les types ci-dessous reproduisent donc le contrat de la charge utile
// décrit dans docs/Developement/Tableau_Protocole_Réseau.md, section « Charge
// utile de la politique ».
//
// Point important : l'agent ne recalcule NI l'empreinte de politique NI celle des
// modules. Le serveur les transmet dans le document (`fingerprint`, `state_key`).
// Deux implémentations du même hachage dans deux modules Go finiraient par
// diverger, et la détection de changement deviendrait silencieusement fausse —
// une machine croirait être à jour alors qu'elle ne l'est pas.
package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Scope d'application d'une politique.
const (
	ScopeMachine = "machine"
	ScopeUser    = "user"
)

// Types de modules du catalogue, tels qu'envoyés par le serveur.
const (
	ModuleSSHServerConfig = "ssh_server_config"
	ModuleSysctl          = "sysctl"
	ModuleSudoersRule     = "sudoers_rule"
	ModulePackage         = "package"
	ModuleSystemdService  = "systemd_service"
	ModuleFileDeploy      = "file_deploy"
	ModuleUserEnv         = "user_env"
	ModuleUserCron        = "user_cron"

	ModuleDirectoryManage = "directory_manage"
	ModuleTemplatedFile   = "templated_file_deploy"
	ModuleTrustedCA       = "trusted_ca"
	ModuleDNSResolver     = "dns_resolver"
	ModulePackageRepo     = "package_repository"
	ModuleFirewallRule    = "firewall_rule"
)

// UserHomePlaceholder est le marqueur remplacé par le home réel de l'utilisateur
// cible dans les chemins de scope user.
const UserHomePlaceholder = "/%h"

// Definition est le contenu d'une valeur nommée référencée par un paramètre.
//
// L'agent ne connaît PAS le contenu des jeux de commandes : il le reçoit avec le
// module. C'est ce qui permet de créer un jeu custom depuis l'interface sans
// déployer un nouvel agent — sinon un jeu inconnu localement échouerait, quel
// que soit son contenu en base.
type Definition struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Payload string `json:"payload"`
}

// Lines découpe le contenu en lignes utiles (vides et commentaires exclus).
func (d Definition) Lines() []string {
	var out []string
	for _, line := range strings.Split(d.Payload, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// Module est un module de politique reçu du serveur.
type Module struct {
	Type        string                `json:"type"`
	Scope       string                `json:"scope"`
	ApplyOrder  int                   `json:"apply_order"`
	Params      map[string]string     `json:"params"`
	StateKey    string                `json:"state_key"`
	Fingerprint string                `json:"fingerprint"`
	Definitions map[string]Definition `json:"definitions,omitempty"`
}

// Definition retourne le contenu de la valeur nommée référencée par un champ.
func (m Module) Definition(fieldName string) (Definition, bool) {
	if m.Definitions == nil {
		return Definition{}, false
	}
	definition, ok := m.Definitions[fieldName]
	return definition, ok
}

// Param retourne un paramètre, débarrassé de ses blancs de bord.
func (m Module) Param(name string) string { return strings.TrimSpace(m.Params[name]) }

// RawParam retourne un paramètre tel quel, sans rognage.
// À utiliser pour les contenus de fichiers, dont l'indentation est signifiante.
func (m Module) RawParam(name string) string { return m.Params[name] }

// BoolParam interprète un paramètre booléen.
func (m Module) BoolParam(name string) bool { return m.Param(name) == "true" }

// Policy est la politique effective reçue du serveur.
type Policy struct {
	Name        string   `json:"name"`
	Scope       string   `json:"scope"`
	Username    string   `json:"username,omitempty"`
	Version     int      `json:"version"`
	Fingerprint string   `json:"fingerprint"`
	Modules     []Module `json:"modules"`
	Signature   string   `json:"signature,omitempty"`
}

// DecodePolicy lit une politique reçue et vérifie sa cohérence interne.
//
// La validation porte sur ce dont l'agent a besoin pour travailler : sans
// empreinte de module, il ne peut pas décider quoi réappliquer ; sans clé
// d'état, il ne peut pas suivre le module d'une fois sur l'autre. Un document
// incomplet est rejeté plutôt qu'appliqué à moitié.
func DecodePolicy(payload []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("politique illisible : %v", err)
	}
	if p.Scope != ScopeMachine && p.Scope != ScopeUser {
		return nil, fmt.Errorf("scope de politique invalide : %q", p.Scope)
	}
	if strings.TrimSpace(p.Fingerprint) == "" {
		return nil, fmt.Errorf("politique sans empreinte")
	}
	for i, m := range p.Modules {
		if strings.TrimSpace(m.Type) == "" {
			return nil, fmt.Errorf("module %d sans type", i+1)
		}
		if strings.TrimSpace(m.StateKey) == "" {
			return nil, fmt.Errorf("module %d (%s) sans clé d'état", i+1, m.Type)
		}
		if strings.TrimSpace(m.Fingerprint) == "" {
			return nil, fmt.Errorf("module %d (%s) sans empreinte", i+1, m.Type)
		}
		if m.Params == nil {
			p.Modules[i].Params = map[string]string{}
		}
	}
	SortModules(p.Modules)
	return &p, nil
}

// SortModules trie les modules par ordre d'application.
//
// Le serveur les envoie déjà triés ; on retrie pour ne pas dépendre de cette
// garantie. L'ordre décide de la réussite : un paquet doit être installé avant
// que son service ne soit activé.
func SortModules(modules []Module) {
	sort.SliceStable(modules, func(i, j int) bool {
		if modules[i].ApplyOrder != modules[j].ApplyOrder {
			return modules[i].ApplyOrder < modules[j].ApplyOrder
		}
		if modules[i].Type != modules[j].Type {
			return modules[i].Type < modules[j].Type
		}
		return modules[i].StateKey < modules[j].StateKey
	})
}

// Checksum retourne la somme de contrôle d'une charge réassemblée.
// Doit correspondre à celle annoncée dans le manifeste.
func Checksum(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// ShortFingerprint raccourcit une empreinte pour les journaux.
func ShortFingerprint(fingerprint string) string {
	if fingerprint == "" {
		return "none"
	}
	if len(fingerprint) <= 12 {
		return fingerprint
	}
	return fingerprint[:12] + "…"
}
