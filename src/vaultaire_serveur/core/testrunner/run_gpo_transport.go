package testrunner

import (
	"encoding/json"
	"fmt"
	"strings"

	"vaultaire/core/gpo"
)

// Tests des primitives de transport des GPO (trames 05_XX).
//
// Ce qui est vérifié ici est ce qui casse silencieusement en production :
// un découpage qui perd un octet, une empreinte qui change quand elle ne
// devrait pas, ou une charge qui se réassemble en JSON valide mais amputé.
func testGPOTransport() []Result {
	var out []Result

	installFixture(baseFixture())
	defer func() {
		gpo.SetRestrictionProvider(nil)
		gpo.InvalidateRestrictionCache()
	}()

	// --- Politique de référence -------------------------------------------
	policy := gpo.Policy{
		Name: "effective_machine", Scope: gpo.ScopeMachine, Enabled: true, Version: 4,
		Modules: []gpo.Module{
			{Type: gpo.ModuleSysctl, Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "0"}},
			{Type: gpo.ModuleSystemdService, Params: map[string]string{
				"service": "telnet.socket", "enabled": "disabled", "state": "stopped", "masked": "true"}},
		},
	}
	if err := gpo.ValidatePolicy(&policy); err != nil {
		out = append(out, Result{"GPO/transport: politique de reference valide", false, err.Error()})
		return out
	}
	out = append(out, Result{"GPO/transport: politique de reference valide", true, ""})

	// --- Clés d'état -------------------------------------------------------
	keys := map[string]string{}
	for _, m := range policy.Modules {
		keys[m.Type] = gpo.ModuleStateKey(m)
	}
	expected := keys[gpo.ModuleSysctl] == "sysctl:net.ipv4.ip_forward" &&
		keys[gpo.ModuleSystemdService] == "systemd_service:telnet.socket"
	out = append(out, Result{"GPO/transport: cles d'etat stables et lisibles", expected,
		fmt.Sprintf("obtenu %v", keys)})

	// --- Empreinte de module ----------------------------------------------
	// Elle ne doit dépendre que du type, du scope et des paramètres : réordonner
	// le catalogue ne doit pas provoquer une réapplication de tout le parc.
	m1 := policy.Modules[0]
	m2 := m1
	m2.ApplyOrder = m1.ApplyOrder + 100
	fp1, err1 := gpo.ModuleFingerprint(m1)
	fp2, err2 := gpo.ModuleFingerprint(m2)
	out = append(out, Result{"GPO/transport: empreinte de module insensible a l'ordre d'application",
		err1 == nil && err2 == nil && fp1 != "" && fp1 == fp2, fmt.Sprintf("fp1=%s fp2=%s", fp1, fp2)})

	m3 := m1
	m3.Params = map[string]string{"key": "net.ipv4.ip_forward", "value": "1"}
	fp3, _ := gpo.ModuleFingerprint(m3)
	out = append(out, Result{"GPO/transport: empreinte de module sensible aux parametres", fp1 != fp3,
		"un changement de valeur doit changer l'empreinte"})

	// --- Préparation du transfert -----------------------------------------
	transfer, err := gpo.PrepareTransfer(policy, "")
	if err != nil {
		out = append(out, Result{"GPO/transport: preparation du transfert", false, err.Error()})
		return out
	}
	manifest := transfer.Manifest
	out = append(out, Result{"GPO/transport: preparation du transfert", true, ""})

	coherent := manifest.ChunkCount >= 1 &&
		manifest.TotalSize == transfer.PayloadSize() &&
		manifest.ModuleCount == len(policy.Modules) &&
		manifest.Fingerprint != "" && manifest.Checksum != ""
	out = append(out, Result{"GPO/transport: manifeste coherent", coherent,
		fmt.Sprintf("fragments=%d taille=%d modules=%d", manifest.ChunkCount, manifest.TotalSize, manifest.ModuleCount)})

	// L'empreinte de politique ne doit PAS être la somme de contrôle de charge :
	// les confondre ferait dépendre la détection de changement du format de
	// livraison, et un simple ajout de champ réappliquerait tout le parc.
	policyFP, _ := gpo.PolicyHash(policy)
	out = append(out, Result{"GPO/transport: empreinte de politique distincte de la somme de controle",
		manifest.Fingerprint == policyFP && manifest.Fingerprint != manifest.Checksum,
		fmt.Sprintf("politique=%s manifeste=%s controle=%s",
			short(policyFP), short(manifest.Fingerprint), short(manifest.Checksum))})

	// --- Réassemblage ------------------------------------------------------
	var reassembled []byte
	for i := 0; i < manifest.ChunkCount; i++ {
		chunk, err := transfer.Chunk(i)
		if err != nil {
			out = append(out, Result{"GPO/transport: lecture des fragments", false, err.Error()})
			return out
		}
		reassembled = append(reassembled, chunk...)
	}
	out = append(out, Result{"GPO/transport: reassemblage complet",
		len(reassembled) == manifest.TotalSize && gpo.PayloadChecksum(reassembled) == manifest.Checksum,
		fmt.Sprintf("%d octets reassembles sur %d", len(reassembled), manifest.TotalSize)})

	// Un index hors bornes doit être refusé, pas silencieusement borné : c'est ce
	// qui fait répondre 05_11 plutôt que de livrer un fragment vide.
	_, errIdx := transfer.Chunk(manifest.ChunkCount)
	_, errNeg := transfer.Chunk(-1)
	out = append(out, Result{"GPO/transport: index de fragment hors bornes refuse",
		errIdx != nil && errNeg != nil, "devrait refuser"})

	// --- Document de livraison --------------------------------------------
	var delivered gpo.DeliveryPolicy
	if err := json.Unmarshal(reassembled, &delivered); err != nil {
		out = append(out, Result{"GPO/transport: document de livraison lisible", false, err.Error()})
		return out
	}
	complete := delivered.Fingerprint == manifest.Fingerprint &&
		len(delivered.Modules) == len(policy.Modules)
	for _, m := range delivered.Modules {
		if strings.TrimSpace(m.StateKey) == "" || strings.TrimSpace(m.Fingerprint) == "" {
			complete = false
		}
	}
	out = append(out, Result{"GPO/transport: chaque module livre porte sa cle d'etat et son empreinte", complete,
		"l'agent ne recalcule pas ces valeurs, leur absence casserait la detection de changement"})

	// --- Découpage d'une charge volumineuse --------------------------------
	// Un seul file_deploy peut dépasser la taille d'une trame : c'est le cas qui
	// a motivé le découpage, il doit être couvert.
	big := gpo.Policy{
		Name: "effective_machine", Scope: gpo.ScopeMachine, Enabled: true, Version: 1,
		Modules: []gpo.Module{
			{Type: gpo.ModuleFileDeploy, Params: map[string]string{
				"path": "/opt/app/gros.conf", "content": strings.Repeat("x", 100*1024),
				"mode": "0644", "state": "present"}},
		},
	}
	if err := gpo.ValidatePolicy(&big); err != nil {
		out = append(out, Result{"GPO/transport: politique volumineuse valide", false, err.Error()})
		return out
	}
	bigTransfer, err := gpo.PrepareTransfer(big, "")
	if err != nil {
		out = append(out, Result{"GPO/transport: preparation d'une politique volumineuse", false, err.Error()})
		return out
	}
	out = append(out, Result{"GPO/transport: politique volumineuse decoupee en plusieurs fragments",
		bigTransfer.Manifest.ChunkCount > 1,
		fmt.Sprintf("%d octets en %d fragment(s), attendu plusieurs",
			bigTransfer.Manifest.TotalSize, bigTransfer.Manifest.ChunkCount)})

	var bigReassembled []byte
	for i := 0; i < bigTransfer.Manifest.ChunkCount; i++ {
		chunk, _ := bigTransfer.Chunk(i)
		bigReassembled = append(bigReassembled, chunk...)
		if i < bigTransfer.Manifest.ChunkCount-1 && len(chunk) != gpo.ChunkSize {
			out = append(out, Result{"GPO/transport: fragments intermediaires pleins", false,
				fmt.Sprintf("fragment %d fait %d octets au lieu de %d", i, len(chunk), gpo.ChunkSize)})
		}
	}
	out = append(out, Result{"GPO/transport: reassemblage d'une politique volumineuse",
		gpo.PayloadChecksum(bigReassembled) == bigTransfer.Manifest.Checksum,
		"la somme de controle du reassemblage ne correspond pas"})

	// --- Rapport d'application --------------------------------------------
	report := gpo.ApplyReport{
		Scope: gpo.ScopeMachine, Fingerprint: manifest.Fingerprint, Status: gpo.ApplyStatusPartial,
		Modules: []gpo.ModuleReport{
			{ModuleType: gpo.ModuleSysctl, StateKey: "sysctl:net.ipv4.ip_forward", Result: gpo.ApplyResultApplied},
			{ModuleType: gpo.ModuleSystemdService, StateKey: "systemd_service:telnet.socket",
				Result: gpo.ApplyResultFailed, Detail: "unite absente"},
		},
	}
	out = append(out, Result{"GPO/transport: rapport resume et modules en echec identifies",
		len(report.FailedModules()) == 1 && strings.Contains(report.Summary(), "failed=1"),
		report.Summary()})

	valid := gpo.IsValidApplyStatus("partial") && gpo.IsValidApplyResult("unchanged") &&
		!gpo.IsValidApplyStatus("inconnu") && !gpo.IsValidApplyResult("inconnu")
	out = append(out, Result{"GPO/transport: statuts et resultats de rapport valides", valid,
		"la validation des valeurs de rapport est incorrecte"})

	return out
}

// short raccourcit une empreinte pour les messages d'echec.
func short(fingerprint string) string {
	if len(fingerprint) <= 12 {
		return fingerprint
	}
	return fingerprint[:12] + "…"
}
