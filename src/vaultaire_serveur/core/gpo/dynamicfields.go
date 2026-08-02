package gpo

// Déclaration des champs à domaine dynamique.
//
// Ce fichier ne contient AUCUNE valeur de restriction. Il décrit uniquement la
// structure : quels champs de quels modules ont un domaine défini en base, quel
// type de contenu ils portent, et comment les présenter dans l'interface. Cette
// partie appartient au code parce qu'elle est indissociable du catalogue de
// modules — un champ dynamique sans entrée ici ne serait jamais éditable.
//
// Les valeurs, elles, vivent exclusivement en base. Leur peuplement initial est
// dans core/database/db_gpo/seed/gpo_seed.sql, exécuté une seule fois, au premier
// démarrage, quand les tables n'existent pas encore. Aucune liste en dur côté Go
// ne peut donc réapparaître après une suppression faite depuis l'interface.

// dynamicField décrit un champ dont le domaine de valeurs est en base.
type dynamicField struct {
	ModuleType string
	FieldName  string
	Label      string
	// PayloadKind non vide : les valeurs sont des définitions nommées portant un
	// contenu (voir payload.go), et non de simples noms.
	PayloadKind PayloadKind
	// Help est affiché dans l'interface d'administration des restrictions.
	Help string
}

var dynamicFields = []dynamicField{
	{
		ModuleType: ModuleSystemdService, FieldName: "service",
		Label: "Unités systemd gérables",
		Help: "Nom complet de l'unité, extension incluse (ex. mon-monitoring.service). " +
			"Une fois l'unité ajoutée ici, le module GPO permet d'en choisir l'état comme pour n'importe quelle autre. " +
			"Passez le champ en mode motif pour accepter toute une famille d'unités d'un coup.",
	},
	{
		ModuleType: ModuleSysctl, FieldName: "key",
		Label: "Clés sysctl réglables",
		Help:  "Clé sysctl en notation pointée (ex. net.ipv4.ip_forward). Ajoutez ici toute clé propre à votre parc.",
	},
	{
		ModuleType: ModuleSysctl, FieldName: "value",
		Label: "Valeurs sysctl acceptées",
		Help: "Contrôle la forme des valeurs sysctl, pas une liste de valeurs : ce champ est en mode motif. " +
			"Le motif initial n'accepte qu'un entier ou une liste d'entiers, ce qui couvre les clés de durcissement usuelles. " +
			"Élargissez-le si une clé de votre parc attend une valeur textuelle.",
	},
	{
		ModuleType: ModulePackage, FieldName: "package",
		Label: "Paquets gérables",
		Help: "Nom de paquet tel que le gestionnaire de la distribution l'attend. Ajoutez ici vos paquets internes ; " +
			"le module gère ensuite présence, absence et version épinglée.",
	},
	{
		ModuleType: ModuleSudoersRule, FieldName: "command_set",
		Label:       "Jeux de commandes sudo",
		PayloadKind: PayloadCommandList,
		Help: "Un jeu porte un nom et la liste des commandes qu'il autorise. C'est cette liste que l'agent rend " +
			"dans le fichier /etc/sudoers.d/ généré : créer un jeu custom ne demande aucun code côté agent.",
	},
	{
		ModuleType: ModuleUserCron, FieldName: "command_id",
		Label: "Tâches planifiables (user)",
		Help: "Identifiant d'une commande implémentée côté agent client. " +
			"Un identifiant sans implémentation donnera une tâche sans effet.",
	},
	{
		ModuleType: ModuleKernelModulePolicy, FieldName: "module",
		Label: "Modules noyau interdictibles",
		Help: "Nom du module tel que modprobe l'attend (ex. usb-storage). La liste initiale couvre les " +
			"vecteurs de stockage amovible et les protocoles rarement utilisés. Ajoutez-y les modules " +
			"propres à votre parc.",
	},
	{
		ModuleType: ModuleUserShell, FieldName: "shell",
		Label: "Shells attribuables",
		Help: "Chemin absolu d'un shell. /usr/sbin/nologin interdit la connexion interactive, /bin/rbash " +
			"donne un shell restreint. N'ajoutez ici que des shells réellement installés sur le parc : " +
			"un shell inexistant rend le compte inutilisable.",
	},
	{
		ModuleType: ModuleUserGroupMembership, FieldName: "group",
		Label: "Groupes locaux attribuables",
		Help: "ATTENTION — cette liste est un point d'élévation de privilèges. Appartenir à docker, lxd, " +
			"disk ou kvm équivaut en pratique à un accès root sur la machine : ces groupes donnent la main " +
			"sur des ressources permettant de lire ou modifier n'importe quel fichier. N'y placez que des " +
			"groupes dont vous avez évalué la portée. La liste initiale ne contient que des groupes de " +
			"périphériques sans conséquence sur les privilèges.",
	},
	{
		ModuleType: ModulePackageRepo, FieldName: "url",
		Label: "Dépôts de paquets autorisés",
		Help: "URL de base d'un dépôt. Ce champ est en mode motif : le motif initial n'accepte que le HTTPS, " +
			"parce qu'un dépôt en HTTP laisse un intermédiaire réseau substituer les paquets installés en root " +
			"sur tout le parc. Ajoutez ici vos miroirs internes, ou élargissez le motif si vous exploitez un " +
			"dépôt local sur un réseau maîtrisé.",
	},
}

// DynamicFieldDescriptor décrit un champ à domaine dynamique, pour l'interface
// d'administration.
type DynamicFieldDescriptor struct {
	ModuleType  string
	FieldName   string
	Label       string
	Help        string
	PayloadKind PayloadKind
}

// HasPayload indique si le champ porte des définitions à contenu.
func (d DynamicFieldDescriptor) HasPayload() bool { return d.PayloadKind != PayloadNone }

// ModuleLabelFor retourne le libellé du module portant ce champ.
func (d DynamicFieldDescriptor) ModuleLabelFor() string { return ModuleLabel(d.ModuleType) }

// Key retourne la clé d'indexation du champ.
func (d DynamicFieldDescriptor) Key() string { return FieldKey(d.ModuleType, d.FieldName) }

// DynamicFields retourne les champs dont le domaine de valeurs vit en base.
func DynamicFields() []DynamicFieldDescriptor {
	out := make([]DynamicFieldDescriptor, 0, len(dynamicFields))
	for _, f := range dynamicFields {
		out = append(out, DynamicFieldDescriptor{
			ModuleType: f.ModuleType, FieldName: f.FieldName,
			Label: f.Label, Help: f.Help, PayloadKind: f.PayloadKind,
		})
	}
	return out
}

// IsDynamicField indique si les valeurs d'un champ viennent de la base.
func IsDynamicField(moduleType, fieldName string) bool {
	for _, f := range dynamicFields {
		if f.ModuleType == moduleType && f.FieldName == fieldName {
			return true
		}
	}
	return false
}

// userHomePlaceholder est le marqueur substitué par l'agent client par le home
// réel de l'utilisateur cible. Il évite d'écrire des chemins absolus vers
// /home/<user>, qui seraient justes pour un utilisateur et faux pour un autre.
//
// Cette constante est référencée par le SQL de peuplement (préfixes de chemins
// autorisés en scope user) : les deux doivent rester cohérents.
const userHomePlaceholder = "/%h"

// UserHomePlaceholder expose le marqueur de home pour l'interface web.
func UserHomePlaceholder() string { return userHomePlaceholder }
