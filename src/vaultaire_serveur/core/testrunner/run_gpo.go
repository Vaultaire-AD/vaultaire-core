package testrunner

import (
	"fmt"

	"vaultaire/core/gpo"
)

// Tests des garde-fous GPO.
//
// Ce fichier vérifie ce qui doit être REFUSÉ, pas seulement ce qui doit marcher :
// les garanties de sécurité du modèle déclaratif reposent entièrement sur des
// refus (module machine-only en scope user, chemin protégé, variable
// d'environnement détournable, paramètre hors schéma). Un test qui ne teste que
// le chemin heureux ne dirait rien de ces garanties.

// testGPO exécute la suite GPO.
func testGPO() []Result {
	var out []Result
	out = append(out, testGPOScopeGuard()...)
	out = append(out, testGPOPathGuard()...)
	out = append(out, testGPOFieldValidation()...)
	out = append(out, testGPOResolution()...)
	return out
}

// testGPOScopeGuard vérifie qu'aucun module privilégié ne passe en scope user.
func testGPOScopeGuard() []Result {
	var out []Result

	machineOnly := gpo.MachineOnlyModuleTypes()
	if len(machineOnly) == 0 {
		out = append(out, Result{"GPO/scope: catalogue machine-only non vide", false, "aucun module machine-only, le garde-fou serait sans objet"})
		return out
	}
	out = append(out, Result{"GPO/scope: catalogue machine-only non vide", true, ""})

	// Chaque module machine-only doit être refusé en scope user.
	failed := ""
	for _, t := range machineOnly {
		if err := gpo.CheckModuleScope(t, gpo.ScopeUser); err == nil {
			failed += t + " "
		}
	}
	if failed != "" {
		out = append(out, Result{"GPO/scope: refus machine-only en scope user", false, "accepté à tort : " + failed})
	} else {
		out = append(out, Result{"GPO/scope: refus machine-only en scope user", true, ""})
	}

	// Le même refus doit s'appliquer via ValidateModule (le chemin réellement
	// emprunté par l'écriture en base et par le formulaire web).
	_, err := gpo.ValidateModule(gpo.ScopeUser, gpo.Module{
		Type:   gpo.ModuleSudoersRule,
		Params: map[string]string{"group": "pirates", "command_set": "ALL", "nopasswd": "false"},
	})
	out = append(out, Result{"GPO/scope: ValidateModule refuse sudoers en scope user", err != nil, "devrait refuser"})

	// Le scope ScopeBoth doit rester utilisable des deux côtés.
	_, errM := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleFileDeploy,
		Params: map[string]string{"path": "/opt/app/motd", "content": "bonjour", "mode": "0644", "state": "present"},
	})
	out = append(out, Result{"GPO/scope: file_deploy accepté en scope machine", errM == nil, fmt.Sprint(errM)})

	return out
}

// testGPOPathGuard vérifie le filtrage des chemins de fichiers.
func testGPOPathGuard() []Result {
	var out []Result

	// Chemins que personne ne doit pouvoir écrire, dans aucun scope.
	protected := []string{"/etc/sudoers", "/etc/sudoers.d/zz", "/etc/pam.d/sshd", "/etc/shadow",
		"/etc/ssh/sshd_config", "/var/lib/vaultaire/state.json", "/root/.ssh/authorized_keys"}
	bad := ""
	for _, p := range protected {
		if gpo.CheckPath(p, gpo.ScopeMachine) == nil {
			bad += p + " "
		}
	}
	if bad != "" {
		out = append(out, Result{"GPO/path: chemins protégés refusés (machine)", false, "acceptés à tort : " + bad})
	} else {
		out = append(out, Result{"GPO/path: chemins protégés refusés (machine)", true, ""})
	}

	// Traversée de répertoire et chemins relatifs.
	for _, p := range []string{"../etc/passwd", "/opt/../etc/passwd", "relatif/chemin", ""} {
		if gpo.CheckPath(p, gpo.ScopeMachine) == nil {
			out = append(out, Result{"GPO/path: refus de " + p, false, "accepté à tort"})
		}
	}
	out = append(out, Result{"GPO/path: refus traversée et chemins relatifs", true, ""})

	// Scope user : uniquement sous le marqueur de home.
	home := gpo.UserHomePlaceholder()
	if err := gpo.CheckPath(home+"/.config/app.conf", gpo.ScopeUser); err != nil {
		out = append(out, Result{"GPO/path: home autorisé en scope user", false, err.Error()})
	} else {
		out = append(out, Result{"GPO/path: home autorisé en scope user", true, ""})
	}
	userBad := ""
	for _, p := range []string{"/etc/hosts", "/usr/local/bin/x", "/var/tmp/x", home + "/.ssh/authorized_keys", home + "/.bash_profile"} {
		if gpo.CheckPath(p, gpo.ScopeUser) == nil {
			userBad += p + " "
		}
	}
	if userBad != "" {
		out = append(out, Result{"GPO/path: hors-home et fichiers de connexion refusés (user)", false, "acceptés à tort : " + userBad})
	} else {
		out = append(out, Result{"GPO/path: hors-home et fichiers de connexion refusés (user)", true, ""})
	}

	return out
}

// testGPOFieldValidation vérifie la validation par schéma.
func testGPOFieldValidation() []Result {
	var out []Result

	// Paramètre hors schéma : doit être refusé, pas ignoré.
	_, err := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSysctl,
		Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "0", "commande_cachee": "rm -rf /"},
	})
	out = append(out, Result{"GPO/champ: paramètre hors schéma refusé", err != nil, "devrait refuser"})

	// Valeur d'enum hors liste (clé sysctl non whitelistée).
	_, err = gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSysctl,
		Params: map[string]string{"key": "kernel.core_pattern", "value": "|/tmp/x"},
	})
	out = append(out, Result{"GPO/champ: clé sysctl hors liste blanche refusée", err != nil, "devrait refuser"})

	// Variable d'environnement détournable.
	_, err = gpo.ValidateModule(gpo.ScopeUser, gpo.Module{
		Type:   gpo.ModuleUserEnv,
		Params: map[string]string{"name": "LD_PRELOAD", "value": "/tmp/eve.so"},
	})
	out = append(out, Result{"GPO/champ: LD_PRELOAD refusé", err != nil, "devrait refuser"})

	// Variable d'environnement légitime.
	_, err = gpo.ValidateModule(gpo.ScopeUser, gpo.Module{
		Type:   gpo.ModuleUserEnv,
		Params: map[string]string{"name": "EDITOR", "value": "vim"},
	})
	out = append(out, Result{"GPO/champ: variable légitime acceptée", err == nil, fmt.Sprint(err)})

	// Combinaison sudo ALL + NOPASSWD : refus sémantique.
	_, err = gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSudoersRule,
		Params: map[string]string{"group": "ops", "command_set": "ALL", "nopasswd": "true"},
	})
	out = append(out, Result{"GPO/champ: sudo ALL+NOPASSWD refusé", err != nil, "devrait refuser"})

	// SSH : couper mot de passe ET clé rendrait les machines inaccessibles.
	_, err = gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type: gpo.ModuleSSHServerConfig,
		Params: map[string]string{
			"permit_root_login": "no", "password_authentication": "no", "pubkey_authentication": "no",
			"allow_tcp_forwarding": "unchanged", "x11_forwarding": "unchanged",
		},
	})
	out = append(out, Result{"GPO/champ: SSH sans aucune méthode d'auth refusé", err != nil, "devrait refuser"})

	// Cron : expression invalide.
	_, err = gpo.ValidateModule(gpo.ScopeUser, gpo.Module{
		Type:   gpo.ModuleUserCron,
		Params: map[string]string{"schedule": "tous les jours", "command_id": "backup_home", "state": "present"},
	})
	out = append(out, Result{"GPO/champ: expression cron invalide refusée", err != nil, "devrait refuser"})

	// Permissions octales avec bit setuid (4 chiffres) refusées.
	_, err = gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleFileDeploy,
		Params: map[string]string{"path": "/opt/app/tool", "content": "x", "mode": "4755", "state": "present"},
	})
	out = append(out, Result{"GPO/champ: mode setuid refusé", err != nil, "devrait refuser"})

	// Doublon de clé naturelle dans une même GPO.
	policy := &gpo.Policy{Name: "test_doublon", Scope: gpo.ScopeMachine, Enabled: true, Version: 1, Modules: []gpo.Module{
		{Type: gpo.ModuleSysctl, Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "0"}},
		{Type: gpo.ModuleSysctl, Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "1"}},
	}}
	out = append(out, Result{"GPO/champ: doublon de clé sysctl refusé", gpo.ValidatePolicy(policy) != nil, "devrait refuser"})

	return out
}

// testGPOResolution vérifie l'ordre d'application, la détection de conflit et la
// stabilité de l'empreinte.
func testGPOResolution() []Result {
	var out []Result

	base := gpo.Policy{Name: "base", Scope: gpo.ScopeMachine, Enabled: true, Version: 1, Modules: []gpo.Module{
		{Type: gpo.ModuleSystemdService, Params: map[string]string{"service": "telnet.socket", "enabled": "disabled", "state": "stopped", "masked": "true"}},
		{Type: gpo.ModuleSysctl, Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "0"}},
	}}
	if err := gpo.ValidatePolicy(&base); err != nil {
		out = append(out, Result{"GPO/résolution: politique de référence valide", false, err.Error()})
		return out
	}
	out = append(out, Result{"GPO/résolution: politique de référence valide", true, ""})

	// Après validation, sysctl (ordre 11) doit précéder systemd_service (ordre 21)
	// même s'il a été saisi en second.
	if len(base.Modules) == 2 && base.Modules[0].Type == gpo.ModuleSysctl {
		out = append(out, Result{"GPO/résolution: ordre d'application imposé", true, ""})
	} else {
		out = append(out, Result{"GPO/résolution: ordre d'application imposé", false, fmt.Sprintf("ordre obtenu : %v", moduleTypeList(base.Modules))})
	}

	// Deux GPO réglant la même clé sysctl : conflit signalé, pas résolu.
	other := gpo.Policy{Name: "autre", Scope: gpo.ScopeMachine, Enabled: true, Version: 1, Modules: []gpo.Module{
		{Type: gpo.ModuleSysctl, Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "1"}},
	}}
	if err := gpo.ValidatePolicy(&other); err != nil {
		out = append(out, Result{"GPO/résolution: seconde politique valide", false, err.Error()})
		return out
	}
	res := gpo.Resolve([]gpo.Policy{base, other})
	out = append(out, Result{"GPO/résolution: conflit inter-GPO détecté", res.HasConflicts(), "aucun conflit signalé alors que deux GPO règlent la même clé"})

	_, err := gpo.BuildPolicyForDelivery(gpo.ScopeMachine, []gpo.Policy{base, other})
	out = append(out, Result{"GPO/résolution: livraison refusée en cas de conflit", err != nil, "devrait refuser"})

	// Une GPO désactivée ne doit pas entrer dans la résolution.
	disabled := other
	disabled.Enabled = false
	res = gpo.Resolve([]gpo.Policy{base, disabled})
	out = append(out, Result{"GPO/résolution: GPO désactivée ignorée", !res.HasConflicts() && len(res.Machine) == 2,
		fmt.Sprintf("conflits=%v modules=%d", res.HasConflicts(), len(res.Machine))})

	// L'empreinte doit être stable quel que soit l'ordre des modules en mémoire.
	h1, err1 := gpo.PolicyHash(base)
	shuffled := base
	shuffled.Modules = []gpo.Module{base.Modules[1], base.Modules[0]}
	h2, err2 := gpo.PolicyHash(shuffled)
	out = append(out, Result{"GPO/résolution: empreinte stable et indépendante de l'ordre",
		err1 == nil && err2 == nil && h1 != "" && h1 == h2, fmt.Sprintf("h1=%s h2=%s", h1, h2)})

	return out
}

// moduleTypeList extrait les types de modules, pour les messages d'échec.
func moduleTypeList(modules []gpo.Module) []string {
	out := make([]string, 0, len(modules))
	for _, m := range modules {
		out = append(out, m.Type)
	}
	return out
}
