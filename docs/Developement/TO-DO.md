Une fois une action faite est validé definitevement c'est a un humain de déplacer la taches dans le dossier DO et ranger le changement dans la bonne version et d'ajouter les changemnt dans Version_History.md


1.[FAIT-H] [DOC]mettre a jour la Documentation pour séparé entierement les GPO voir trames struct (si il a des changement a faire dans le protcole dabord mettre ajour la documentation et demander ensuite validation)
2.[EN COURS] [GPO] Ajout de nouveaux Module
            [FAIT] Ordre d'application repense en phases (fichiers -> sources -> paquets -> config -> services).
                   L'ancien ordre mettait les fichiers APRES les services : un service demarrait sur la conf
                   par defaut du paquet. Voir GPO.md section 5.
            [FAIT] 6 modules : directory_manage, templated_file_deploy, trusted_ca, dns_resolver,
                   package_repository, firewall_rule.
            [RESTE] les ~24 autres modules listes ci-dessous.
            A. Modules manquants — Sécurité & réseau
Module	Description	Scope
firewall_rule	Règles nftables/firewalld dédiées (table séparée, jamais mélangée aux règles manuelles)	Machine
pam_policy	Complexité mot de passe (pam_pwquality), verrouillage après N échecs (pam_faillock), délai anti-bruteforce	Machine
auditd_rule	Règles d'audit (auditctl//etc/audit/rules.d/) — qui a modifié quoi, tracé au niveau noyau	Machine
selinux_mode	Mode SELinux (enforcing/permissive) + booleans spécifiques, whitelist comme pour sysctl	Machine
trusted_ca	Déploiement/révocation de CA internes dans le trust store	Machine
dns_resolver	Serveurs DNS, domaine de recherche, entrées hosts forcées (bloc balisé)	Machine
mount_hardening	Options de montage forcées (noexec, nodev, nosuid sur /tmp, /home)	Machine
kernel_module_policy	Blacklist de modules noyau (ex: usb-storage pour bloquer les clés USB)	Machine
local_account_policy	Désactive l'auth password pour les comptes locaux non-Vaultaire, expiration de compte (chage)	Machine
ssh_known_hosts	Entrées known_hosts globales pré-remplies, StrictHostKeyChecking	Machine ou User
            B. Modules manquants — Système & services
Module	Description	Scope
package_repository	Définit les dépôts autorisés (apt/yum) — nécessaire pour que package n'installe que depuis des sources de confiance	Machine
log_policy	Rotation/rétention (logrotate.d, journald.conf.d)	Machine
ntp_config	Serveurs NTP/chrony	Machine
boot_params	Paramètres kernel au boot (GRUB), distinct de sysctl (runtime)	Machine
update_policy	Mises à jour automatiques on/off, fenêtre de maintenance	Machine
system_env	/etc/environment — variables globales, distinct de user_env	Machine
resource_limits	ulimits/slices systemd machine-wide (pas seulement user cgroups)	Machine
            C. Modules manquants — Fichiers
Module	Description	Scope
directory_manage	Création de dossier avec perms/owner (le catalogue actuel ne gère que des fichiers)	Both
file_acl	ACL POSIX (setfacl) au-delà de owner/group/mode simple	Both
file_retention	Purge de fichiers selon âge/pattern (ex: vieux logs applicatifs)	Machine
templated_file_deploy	Variante de file_deploy avec substitution de variables ({{hostname}}, {{username}}) — évite de dupliquer un module par machine	Both
            D. Modules manquants — Environnement utilisateur
Module	Description	Scope
user_shell	Force le shell de connexion (chsh géré, ou shell restreint rbash)	User
user_resource_limits	Quota CPU/mémoire par utilisateur (cgroups user slice) — discuté hier, absent du catalogue actuel	User
user_git_config	.gitconfig par champs contrôlés (pas de fichier brut)	User
user_ssh_client_config	~/.ssh/config (proxy jump, host aliases)	User
user_password_policy	Force changement au prochain login, expiration individuelle	User
user_group_membership	Ajout/retrait d'un groupe POSIX local (distinct de sudoers_rule, plus générique)	User
4.[GPO] - Détection de dérive (drift detection)
            Rien dans le catalogue ne vérifie qu'un module resté "appliqué avec succès" (version à jour dans applied_policies.json) correspond encore à l'état réel du système — un admin qui modifie manuellement sshd_config.d/99-vaultaire-gpo.conf en SSH direct fausserait l'état sans que rien ne le détecte. Il faut un scan périodique de conformité, pas seulement une application ponctuelle.
7.[GPO] - Reporting de conformité centralisé
            Vue d'ensemble côté serveur : quelle version de policy chaque machine a effectivement appliquée avec succès, quelles machines sont en échec/en retard — sans ça, tu n'as aucune visibilité sur l'état réel du parc.