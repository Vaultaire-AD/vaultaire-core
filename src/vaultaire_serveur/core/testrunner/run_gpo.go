package testrunner

import (
	"fmt"

	"vaultaire/core/gpo"
)

// Tests des garde-fous GPO.
//
// Ce fichier vérifie ce qui doit être REFUSÉ, pas seulement ce qui doit marcher :
// les garanties du modèle déclaratif reposent entièrement sur des refus (module
// machine-only en scope user, chemin protégé, variable d'environnement
// détournable, paramètre hors schéma, valeur hors domaine).
//
// Les restrictions vivent en base et leur lecture est fail-closed : sans
// fournisseur installé, RIEN n'est autorisé. Ces tests installent donc leur
// propre fournisseur. La fixture ci-dessous est volontairement minimale — juste
// ce que les tests exercent — et n'a pas à rester synchronisée avec le script de
// peuplement : elle sert à tester la mécanique, pas le contenu livré.

// fakeRestrictions injecte un jeu de restrictions en test, sans base.
type fakeRestrictions struct{ set gpo.RestrictionSet }

func (f fakeRestrictions) LoadRestrictions() (gpo.RestrictionSet, error) { return f.set, nil }

// failingRestrictions simule une base injoignable.
type failingRestrictions struct{}

func (failingRestrictions) LoadRestrictions() (gpo.RestrictionSet, error) {
	return gpo.RestrictionSet{}, fmt.Errorf("base injoignable (simulé)")
}

// baseFixture construit le jeu de restrictions utilisé par les tests.
func baseFixture() gpo.RestrictionSet {
	svcKey := gpo.FieldKey(gpo.ModuleSystemdService, "service")
	sysKey := gpo.FieldKey(gpo.ModuleSysctl, "key")
	sysVal := gpo.FieldKey(gpo.ModuleSysctl, "value")
	pkgKey := gpo.FieldKey(gpo.ModulePackage, "package")
	cronKey := gpo.FieldKey(gpo.ModuleUserCron, "command_id")
	sudoKey := gpo.FieldKey(gpo.ModuleSudoersRule, "command_set")

	values := func(moduleType, field string, list ...string) []gpo.AllowedValue {
		out := make([]gpo.AllowedValue, 0, len(list))
		for _, v := range list {
			out = append(out, gpo.AllowedValue{ModuleType: moduleType, FieldName: field, Value: v})
		}
		return out
	}

	home := gpo.UserHomePlaceholder()
	rs := gpo.RestrictionSet{
		AllowedValues: map[string][]gpo.AllowedValue{
			svcKey:  values(gpo.ModuleSystemdService, "service", "telnet.socket", "auditd.service", "rsyslog.service"),
			sysKey:  values(gpo.ModuleSysctl, "key", "net.ipv4.ip_forward", "kernel.sysrq"),
			pkgKey:  values(gpo.ModulePackage, "package", "telnet", "auditd"),
			cronKey: values(gpo.ModuleUserCron, "command_id", "backup_home", "cleanup_tmp"),
		},
		Definitions: map[string][]gpo.ValueDefinition{
			sudoKey: {
				{ModuleType: gpo.ModuleSudoersRule, FieldName: "command_set", Name: "ALL",
					Kind: gpo.PayloadCommandList, Payload: "ALL"},
				{ModuleType: gpo.ModuleSudoersRule, FieldName: "command_set", Name: "service_control",
					Kind: gpo.PayloadCommandList,
					Payload: "/usr/bin/systemctl start\n/usr/bin/systemctl stop\n/usr/bin/systemctl restart"},
			},
		},
		FieldRules: map[string]gpo.FieldRule{
			svcKey:  {ModuleType: gpo.ModuleSystemdService, FieldName: "service", Mode: gpo.FieldModeList},
			sysKey:  {ModuleType: gpo.ModuleSysctl, FieldName: "key", Mode: gpo.FieldModeList},
			sysVal:  {ModuleType: gpo.ModuleSysctl, FieldName: "value", Mode: gpo.FieldModePattern, AllowPattern: `^-?[0-9]+( -?[0-9]+)*$`},
			pkgKey:  {ModuleType: gpo.ModulePackage, FieldName: "package", Mode: gpo.FieldModeList},
			cronKey: {ModuleType: gpo.ModuleUserCron, FieldName: "command_id", Mode: gpo.FieldModeList},
			sudoKey: {ModuleType: gpo.ModuleSudoersRule, FieldName: "command_set", Mode: gpo.FieldModeList},
		},
		PathRules: []gpo.PathRule{
			{Scope: gpo.PathScopeAny, Deny: true, Prefix: "/etc/pam.d/"},
			{Scope: gpo.PathScopeAny, Deny: true, Prefix: "/etc/security/"},
			{Scope: gpo.PathScopeAny, Deny: true, Prefix: "/etc/sudoers"},
			{Scope: gpo.PathScopeAny, Deny: true, Prefix: "/etc/sudoers.d/"},
			{Scope: gpo.PathScopeAny, Deny: true, Prefix: "/etc/shadow"},
			{Scope: gpo.PathScopeAny, Deny: true, Prefix: "/etc/ssh/sshd_config"},
			{Scope: gpo.PathScopeAny, Deny: true, Prefix: "/var/lib/vaultaire/"},
			{Scope: gpo.PathScopeAny, Deny: true, Prefix: "/root/.ssh/"},
			{Scope: string(gpo.ScopeUser), Deny: true, Prefix: "/etc/"},
			{Scope: string(gpo.ScopeUser), Deny: true, Prefix: "/usr/"},
			{Scope: string(gpo.ScopeUser), Deny: true, Prefix: "/var/"},
			{Scope: string(gpo.ScopeUser), Deny: true, Prefix: home + "/.ssh/"},
			{Scope: string(gpo.ScopeUser), Deny: true, Prefix: home + "/.bash_profile"},
			{Scope: string(gpo.ScopeUser), Deny: false, Prefix: home + "/"},
		},
		EnvDenied: []gpo.EnvRule{{Name: "LD_PRELOAD"}, {Name: "PATH"}, {Name: "BASH_ENV"}},
	}
	return rs
}

// installFixture installe la fixture de test comme source de restrictions.
func installFixture(rs gpo.RestrictionSet) {
	gpo.SetRestrictionProvider(fakeRestrictions{set: rs})
	gpo.InvalidateRestrictionCache()
}

// testGPO exécute la suite GPO.
func testGPO() []Result {
	// Toutes les sous-suites partent de la même fixture ; celles qui la modifient
	// la réinstallent. Le fournisseur est retiré à la fin pour ne pas laisser un
	// état global aux suites suivantes.
	defer func() {
		gpo.SetRestrictionProvider(nil)
		gpo.InvalidateRestrictionCache()
	}()

	var out []Result
	out = append(out, testGPOFailClosed()...)

	installFixture(baseFixture())
	out = append(out, testGPOScopeGuard()...)
	out = append(out, testGPOPathGuard()...)
	out = append(out, testGPOFieldValidation()...)
	out = append(out, testGPORestrictions()...)
	out = append(out, testGPOPayload()...)

	installFixture(baseFixture())
	out = append(out, testGPOResolution()...)

	// Transport (trames 05_XX) : découpage, empreintes, réassemblage, rapport.
	out = append(out, testGPOTransport()...)
	return out
}

// testGPOFailClosed vérifie qu'en l'absence de source de restrictions, ou en cas
// d'échec de lecture, plus rien n'est autorisé.
func testGPOFailClosed() []Result {
	var out []Result

	gpo.SetRestrictionProvider(nil)
	gpo.InvalidateRestrictionCache()

	rs := gpo.Restrictions()
	empty := len(rs.Values(gpo.ModuleSystemdService, "service")) == 0 &&
		len(rs.DefinitionsFor(gpo.ModuleSudoersRule, "command_set")) == 0
	out = append(out, Result{"GPO/fail-closed: sans source, aucune valeur autorisée", empty,
		"des valeurs subsistent alors qu'aucune source n'est installée"})
	out = append(out, Result{"GPO/fail-closed: erreur de chargement signalée",
		gpo.LastRestrictionError() != "", "aucune erreur remontée"})

	_, err := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSysctl,
		Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "0"},
	})
	out = append(out, Result{"GPO/fail-closed: aucun module ne valide sans restrictions", err != nil,
		"un module a validé alors que les restrictions ne sont pas chargées"})

	// Une lecture en erreur doit se comporter comme une absence de source, et non
	// retomber sur un socle codé en dur.
	gpo.SetRestrictionProvider(failingRestrictions{})
	gpo.InvalidateRestrictionCache()
	rs = gpo.Restrictions()
	out = append(out, Result{"GPO/fail-closed: lecture en erreur ne rétablit aucun socle",
		len(rs.Values(gpo.ModuleSysctl, "key")) == 0, "des valeurs sont apparues malgré l'échec de lecture"})
	out = append(out, Result{"GPO/fail-closed: état de chargement consultable",
		!gpo.RestrictionsAreLoaded(), "les restrictions sont annoncées comme chargées à tort"})

	return out
}

// testGPOScopeGuard vérifie qu'aucun module privilégié ne passe en scope user.
func testGPOScopeGuard() []Result {
	var out []Result

	machineOnly := gpo.MachineOnlyModuleTypes()
	if len(machineOnly) == 0 {
		out = append(out, Result{"GPO/scope: catalogue machine-only non vide", false,
			"aucun module machine-only, le garde-fou serait sans objet"})
		return out
	}
	out = append(out, Result{"GPO/scope: catalogue machine-only non vide", true, ""})

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

	// Le même refus doit s'appliquer via ValidateModule, chemin réellement
	// emprunté par l'écriture en base et par le formulaire web.
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

	protected := []string{"/etc/sudoers", "/etc/sudoers.d/zz", "/etc/pam.d/sshd", "/etc/shadow",
		"/etc/ssh/sshd_config", "/var/lib/vaultaire/state.json", "/root/.ssh/authorized_keys"}
	bad := ""
	for _, p := range protected {
		if gpo.CheckPath(p, gpo.ScopeMachine) == nil {
			bad += p + " "
		}
	}
	if bad != "" {
		out = append(out, Result{"GPO/path: chemins refusés bien refusés (machine)", false, "acceptés à tort : " + bad})
	} else {
		out = append(out, Result{"GPO/path: chemins refusés bien refusés (machine)", true, ""})
	}

	malformed := ""
	for _, p := range []string{"../etc/passwd", "/opt/../etc/passwd", "relatif/chemin", ""} {
		if gpo.CheckPath(p, gpo.ScopeMachine) == nil {
			malformed += p + " "
		}
	}
	if malformed != "" {
		out = append(out, Result{"GPO/path: refus traversée et chemins relatifs", false, "acceptés à tort : " + malformed})
	} else {
		out = append(out, Result{"GPO/path: refus traversée et chemins relatifs", true, ""})
	}

	home := gpo.UserHomePlaceholder()
	if err := gpo.CheckPath(home+"/.config/app.conf", gpo.ScopeUser); err != nil {
		out = append(out, Result{"GPO/path: home autorisé en scope user", false, err.Error()})
	} else {
		out = append(out, Result{"GPO/path: home autorisé en scope user", true, ""})
	}

	userBad := ""
	for _, p := range []string{"/etc/hosts", "/usr/local/bin/x", "/var/tmp/x",
		home + "/.ssh/authorized_keys", home + "/.bash_profile"} {
		if gpo.CheckPath(p, gpo.ScopeUser) == nil {
			userBad += p + " "
		}
	}
	if userBad != "" {
		out = append(out, Result{"GPO/path: hors-home et fichiers de connexion refusés (user)", false,
			"acceptés à tort : " + userBad})
	} else {
		out = append(out, Result{"GPO/path: hors-home et fichiers de connexion refusés (user)", true, ""})
	}

	return out
}

// testGPOFieldValidation vérifie la validation par schéma.
func testGPOFieldValidation() []Result {
	var out []Result

	// Paramètre hors schéma : refusé, pas ignoré.
	_, err := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSysctl,
		Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "0", "commande_cachee": "rm -rf /"},
	})
	out = append(out, Result{"GPO/champ: paramètre hors schéma refusé", err != nil, "devrait refuser"})

	// Clé sysctl hors liste.
	_, err = gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSysctl,
		Params: map[string]string{"key": "kernel.core_pattern", "value": "1"},
	})
	out = append(out, Result{"GPO/champ: clé sysctl hors liste refusée", err != nil, "devrait refuser"})

	// Valeur sysctl : forme contrôlée par la règle sysctl/value (mode motif).
	_, errNum := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSysctl,
		Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "0"},
	})
	_, errTxt := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSysctl,
		Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "pas-un-entier"},
	})
	out = append(out, Result{"GPO/champ: valeur sysctl numérique acceptée, textuelle refusée",
		errNum == nil && errTxt != nil, fmt.Sprintf("num=%v txt=%v", errNum, errTxt)})

	// Variables d'environnement.
	_, errEnvBad := gpo.ValidateModule(gpo.ScopeUser, gpo.Module{
		Type:   gpo.ModuleUserEnv,
		Params: map[string]string{"name": "LD_PRELOAD", "value": "/tmp/eve.so"},
	})
	_, errEnvOK := gpo.ValidateModule(gpo.ScopeUser, gpo.Module{
		Type:   gpo.ModuleUserEnv,
		Params: map[string]string{"name": "EDITOR", "value": "vim"},
	})
	out = append(out, Result{"GPO/champ: LD_PRELOAD refusé, EDITOR accepté",
		errEnvBad != nil && errEnvOK == nil, fmt.Sprintf("bad=%v ok=%v", errEnvBad, errEnvOK)})

	// Sudo : jeu inexistant refusé, jeu défini accepté, ALL+NOPASSWD refusé.
	_, errUnknown := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSudoersRule,
		Params: map[string]string{"group": "ops", "command_set": "jeu_inexistant", "nopasswd": "false"},
	})
	out = append(out, Result{"GPO/champ: jeu de commandes sudo non défini refusé", errUnknown != nil, "devrait refuser"})

	_, errKnown := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSudoersRule,
		Params: map[string]string{"group": "ops", "command_set": "service_control", "nopasswd": "false"},
	})
	out = append(out, Result{"GPO/champ: jeu de commandes sudo défini accepté", errKnown == nil, fmt.Sprint(errKnown)})

	_, errAll := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSudoersRule,
		Params: map[string]string{"group": "ops", "command_set": "ALL", "nopasswd": "true"},
	})
	out = append(out, Result{"GPO/champ: sudo ALL+NOPASSWD refusé", errAll != nil, "devrait refuser"})

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

	// Permissions octales avec bit setuid refusées.
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

// testGPORestrictions vérifie que le domaine des champs vient bien de la source
// injectée, et que les trois modes se comportent comme annoncé.
func testGPORestrictions() []Result {
	var out []Result

	// 1. Mode liste : une valeur ajoutée par la source devient acceptée, alors
	//    qu'elle n'existe nulle part dans le code.
	custom := baseFixture()
	key := gpo.FieldKey(gpo.ModuleSystemdService, "service")
	custom.AllowedValues[key] = append(custom.AllowedValues[key], gpo.AllowedValue{
		ModuleType: gpo.ModuleSystemdService, FieldName: "service", Value: "mon-monitoring.service",
	})
	installFixture(custom)

	_, err := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type: gpo.ModuleSystemdService,
		Params: map[string]string{
			"service": "mon-monitoring.service", "enabled": "enabled", "state": "started", "masked": "false",
		},
	})
	out = append(out, Result{"GPO/restrictions: service custom accepté après ajout en base", err == nil, fmt.Sprint(err)})

	// 2. Le catalogue résolu doit exposer la nouvelle valeur à l'interface web.
	out = append(out, Result{"GPO/restrictions: valeur custom visible dans le catalogue résolu",
		fieldOffers(gpo.ModuleSystemdService, "service", "mon-monitoring.service"),
		"la valeur ajoutée n'apparaît pas dans les options du champ"})

	// 3. Mode motif : accepte une famille, refuse ce qui sort du motif.
	pattern := baseFixture()
	pattern.FieldRules[key] = gpo.FieldRule{
		ModuleType: gpo.ModuleSystemdService, FieldName: "service",
		Mode:         gpo.FieldModePattern,
		AllowPattern: `^[a-z0-9@._-]+\.(service|socket|timer)$`,
		DenyPattern:  `^(sshd|systemd-)`,
	}
	installFixture(pattern)

	_, errOK := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type: gpo.ModuleSystemdService,
		Params: map[string]string{
			"service": "agent-maison.timer", "enabled": "enabled", "state": "started", "masked": "false",
		},
	})
	_, errKO := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type: gpo.ModuleSystemdService,
		Params: map[string]string{
			"service": "PasDeExtension", "enabled": "enabled", "state": "started", "masked": "false",
		},
	})
	out = append(out, Result{"GPO/restrictions: mode motif accepte le conforme, refuse le reste",
		errOK == nil && errKO != nil, fmt.Sprintf("ok=%v ko=%v", errOK, errKO)})

	// 4. Le motif d'exclusion est prioritaire, même sur une valeur conforme au
	//    motif d'autorisation.
	_, err = gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type: gpo.ModuleSystemdService,
		Params: map[string]string{
			"service": "sshd.service", "enabled": "disabled", "state": "stopped", "masked": "false",
		},
	})
	out = append(out, Result{"GPO/restrictions: motif d'exclusion prioritaire", err != nil, "devrait refuser"})

	// 5. Mode libre : plus de contrainte de domaine, mais l'exclusion tient.
	free := baseFixture()
	free.FieldRules[key] = gpo.FieldRule{
		ModuleType: gpo.ModuleSystemdService, FieldName: "service",
		Mode: gpo.FieldModeFree, DenyPattern: `^interdit-`,
	}
	installFixture(free)

	_, errFree := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type: gpo.ModuleSystemdService,
		Params: map[string]string{
			"service": "n-importe-quoi", "enabled": "enabled", "state": "started", "masked": "false",
		},
	})
	_, errDenied := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type: gpo.ModuleSystemdService,
		Params: map[string]string{
			"service": "interdit-service", "enabled": "enabled", "state": "started", "masked": "false",
		},
	})
	out = append(out, Result{"GPO/restrictions: mode libre accepte, exclusion refuse",
		errFree == nil && errDenied != nil, fmt.Sprintf("libre=%v exclu=%v", errFree, errDenied)})

	// 6. Retirer une variable de la liste des interdits la rend autorisée : c'est
	//    bien la source qui décide, plus le code.
	envOpen := baseFixture()
	envOpen.EnvDenied = nil
	installFixture(envOpen)
	_, err = gpo.ValidateModule(gpo.ScopeUser, gpo.Module{
		Type:   gpo.ModuleUserEnv,
		Params: map[string]string{"name": "LD_PRELOAD", "value": "/tmp/x.so"},
	})
	out = append(out, Result{"GPO/restrictions: interdictions de variables pilotées par la source", err == nil,
		"la liste vidée devrait tout autoriser : " + fmt.Sprint(err)})

	// 7. Motifs : syntaxe vérifiée avant enregistrement.
	out = append(out, Result{"GPO/restrictions: motif invalide rejeté",
		gpo.ValidatePatternSyntax(`^[a-z`) != nil, "devrait refuser"})
	out = append(out, Result{"GPO/restrictions: motif valide accepté",
		gpo.ValidatePatternSyntax(`^[a-z]+\.service$`) == nil, "devrait accepter"})

	installFixture(baseFixture())
	return out
}

// testGPOPayload vérifie le mécanisme générique des définitions à contenu, dont
// les jeux de commandes sudo sont le premier utilisateur.
func testGPOPayload() []Result {
	var out []Result

	out = append(out, Result{"GPO/payload: command_set identifié comme champ à contenu",
		gpo.FieldHasPayload(gpo.ModuleSudoersRule, "command_set"), "devrait porter un contenu"})
	out = append(out, Result{"GPO/payload: service identifié comme liste simple",
		!gpo.FieldHasPayload(gpo.ModuleSystemdService, "service"), "ne devrait pas porter de contenu"})

	okPayload := "/usr/bin/systemctl restart mon-monitoring.service\n# commentaire ignoré\n/usr/bin/journalctl -u mon-monitoring.service"
	out = append(out, Result{"GPO/payload: liste de commandes valide acceptée",
		gpo.ValidatePayload(gpo.PayloadCommandList, okPayload) == nil,
		fmt.Sprint(gpo.ValidatePayload(gpo.PayloadCommandList, okPayload))})

	rejected := map[string]string{
		"chaînage":         "/usr/bin/systemctl restart x; /bin/sh",
		"substitution":     "/usr/bin/echo $(id)",
		"joker":            "/usr/bin/*",
		"chemin relatif":   "systemctl restart x",
		"ALL combiné":      "ALL\n/usr/bin/ls",
		"contenu vide":     "   \n# rien\n",
		"backtick":         "/usr/bin/echo `id`",
		"guillemet simple": "/usr/bin/find / -name 'x'",
	}
	bad := ""
	for label, payload := range rejected {
		if gpo.ValidatePayload(gpo.PayloadCommandList, payload) == nil {
			bad += label + " "
		}
	}
	if bad != "" {
		out = append(out, Result{"GPO/payload: formes dangereuses refusées", false, "acceptées à tort : " + bad})
	} else {
		out = append(out, Result{"GPO/payload: formes dangereuses refusées", true, ""})
	}

	out = append(out, Result{"GPO/payload: contenu refusé sur un champ sans contenu",
		gpo.ValidatePayload(gpo.PayloadNone, "quelque chose") != nil, "devrait refuser"})
	out = append(out, Result{"GPO/payload: kind inconnu refusé",
		gpo.ValidatePayload(gpo.PayloadKind("inexistant"), "x") != nil, "devrait refuser"})

	// Un jeu custom injecté par la source devient utilisable dans une GPO, sans
	// qu'aucun code n'ait changé — c'est l'objectif du mécanisme.
	custom := baseFixture()
	key := gpo.FieldKey(gpo.ModuleSudoersRule, "command_set")
	custom.Definitions[key] = append(custom.Definitions[key], gpo.ValueDefinition{
		ModuleType: gpo.ModuleSudoersRule, FieldName: "command_set", Name: "monitoring_ops",
		Kind:    gpo.PayloadCommandList,
		Payload: "/usr/bin/systemctl restart mon-monitoring.service",
	})
	installFixture(custom)

	_, err := gpo.ValidateModule(gpo.ScopeMachine, gpo.Module{
		Type:   gpo.ModuleSudoersRule,
		Params: map[string]string{"group": "ops", "command_set": "monitoring_ops", "nopasswd": "false"},
	})
	out = append(out, Result{"GPO/payload: jeu de commandes custom utilisable en GPO", err == nil, fmt.Sprint(err)})

	out = append(out, Result{"GPO/payload: définition custom visible dans les options du champ",
		fieldOffers(gpo.ModuleSudoersRule, "command_set", "monitoring_ops"),
		"la définition n'apparaît pas dans les options"})

	installFixture(baseFixture())
	return out
}

// testGPOResolution vérifie l'ordre d'application, la détection de conflit et la
// stabilité de l'empreinte.
func testGPOResolution() []Result {
	var out []Result

	base := gpo.Policy{Name: "base", Scope: gpo.ScopeMachine, Enabled: true, Version: 1, Modules: []gpo.Module{
		{Type: gpo.ModuleSystemdService, Params: map[string]string{
			"service": "telnet.socket", "enabled": "disabled", "state": "stopped", "masked": "true"}},
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
		out = append(out, Result{"GPO/résolution: ordre d'application imposé", false,
			fmt.Sprintf("ordre obtenu : %v", moduleTypeList(base.Modules))})
	}

	other := gpo.Policy{Name: "autre", Scope: gpo.ScopeMachine, Enabled: true, Version: 1, Modules: []gpo.Module{
		{Type: gpo.ModuleSysctl, Params: map[string]string{"key": "net.ipv4.ip_forward", "value": "1"}},
	}}
	if err := gpo.ValidatePolicy(&other); err != nil {
		out = append(out, Result{"GPO/résolution: seconde politique valide", false, err.Error()})
		return out
	}
	res := gpo.Resolve([]gpo.Policy{base, other})
	out = append(out, Result{"GPO/résolution: conflit inter-GPO détecté", res.HasConflicts(),
		"aucun conflit signalé alors que deux GPO règlent la même clé"})

	_, err := gpo.BuildPolicyForDelivery(gpo.ScopeMachine, []gpo.Policy{base, other})
	out = append(out, Result{"GPO/résolution: livraison refusée en cas de conflit", err != nil, "devrait refuser"})

	disabled := other
	disabled.Enabled = false
	res = gpo.Resolve([]gpo.Policy{base, disabled})
	out = append(out, Result{"GPO/résolution: GPO désactivée ignorée",
		!res.HasConflicts() && len(res.Machine) == 2,
		fmt.Sprintf("conflits=%v modules=%d", res.HasConflicts(), len(res.Machine))})

	h1, err1 := gpo.PolicyHash(base)
	shuffled := base
	shuffled.Modules = []gpo.Module{base.Modules[1], base.Modules[0]}
	h2, err2 := gpo.PolicyHash(shuffled)
	out = append(out, Result{"GPO/résolution: empreinte stable et indépendante de l'ordre",
		err1 == nil && err2 == nil && h1 != "" && h1 == h2, fmt.Sprintf("h1=%s h2=%s", h1, h2)})

	return out
}

// fieldOffers indique si le catalogue résolu propose cette valeur pour ce champ.
func fieldOffers(moduleType, fieldName, value string) bool {
	schema, ok := gpo.SchemaFor(moduleType)
	if !ok {
		return false
	}
	field, has := schema.Field(fieldName)
	if !has {
		return false
	}
	for _, o := range field.Options {
		if o == value {
			return true
		}
	}
	return false
}

// moduleTypeList extrait les types de modules, pour les messages d'échec.
func moduleTypeList(modules []gpo.Module) []string {
	out := make([]string, 0, len(modules))
	for _, m := range modules {
		out = append(out, m.Type)
	}
	return out
}
