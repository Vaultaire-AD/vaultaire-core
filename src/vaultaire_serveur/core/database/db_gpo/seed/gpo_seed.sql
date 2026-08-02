-- Peuplement initial des restrictions GPO.
--
-- Ce fichier est embarqué dans le binaire (go:embed) et exécuté UNE SEULE FOIS,
-- au premier démarrage, quand les tables de restrictions n'existent pas encore.
-- Il est aussi rejoué par l'action « Réinitialiser » de la page
-- Admin -> GPO -> Restrictions, qui purge d'abord les tables.
--
-- Aucune de ces valeurs n'existe en dur dans le code Go : une valeur supprimée
-- depuis l'interface web ne peut donc pas réapparaître au redémarrage.
--
-- Conventions :
--   * une instruction par bloc, séparée par un point-virgule en fin de ligne ;
--   * INSERT IGNORE partout, pour que le rejeu soit sans effet de bord ;
--   * les commentaires -- sont retirés avant exécution.
--
-- Rappel : le marqueur /%h dans les préfixes de chemins est substitué par
-- l'agent client par le home réel de l'utilisateur cible. Il doit rester
-- identique à gpo.userHomePlaceholder (core/gpo/dynamicfields.go).

-- ---------------------------------------------------------------------------
-- Règles de validation par champ (mode + motifs)
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO gpo_field_rule (module_type, field_name, mode, allow_pattern, deny_pattern, updated_by) VALUES
  ('systemd_service', 'service',     'list',    NULL, NULL, 'system'),
  ('sysctl',          'key',         'list',    NULL, NULL, 'system'),
  ('sysctl',          'value',       'pattern', '^-?[0-9]+( -?[0-9]+)*$', NULL, 'system'),
  ('package',         'package',     'list',    NULL, NULL, 'system'),
  ('sudoers_rule',    'command_set', 'list',    NULL, NULL, 'system'),
  ('user_cron',       'command_id',  'list',    NULL, NULL, 'system'),
  -- Depots de paquets : mode motif, HTTPS exige.
  -- Un depot en HTTP laisse un intermediaire reseau substituer les paquets, qui
  -- sont ensuite installes en root sur tout le parc. Le motif est elargissable
  -- depuis l'interface pour un miroir local sur reseau maitrise.
  ('package_repository', 'url',        'pattern', '^https://[A-Za-z0-9._-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$', NULL, 'system'),
  ('kernel_module_policy',    'module', 'list',    NULL, NULL, 'system'),
  ('user_shell',              'shell',  'list',    NULL, NULL, 'system'),
  ('user_group_membership',   'group',  'list',    NULL, NULL, 'system');

-- ---------------------------------------------------------------------------
-- Unités systemd gérables
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO gpo_restriction (kind, module_type, field_name, scope, value, updated_by) VALUES
  ('allow_value', 'systemd_service', 'service', 'any', 'apparmor.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'auditd.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'avahi-daemon.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'avahi-daemon.socket', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'chronyd.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'cups.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'cups.socket', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'fail2ban.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'firewalld.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'nftables.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'nfs-server.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'ntp.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'rpcbind.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'rpcbind.socket', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'rsyslog.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'smbd.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'snapd.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'systemd-timesyncd.service', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'telnet.socket', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'tftp.socket', 'system'),
  ('allow_value', 'systemd_service', 'service', 'any', 'vsftpd.service', 'system');

-- ---------------------------------------------------------------------------
-- Clés sysctl réglables (durcissement réseau et noyau)
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO gpo_restriction (kind, module_type, field_name, scope, value, updated_by) VALUES
  ('allow_value', 'sysctl', 'key', 'any', 'kernel.dmesg_restrict', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'kernel.kptr_restrict', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'kernel.randomize_va_space', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'kernel.sysrq', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'kernel.unprivileged_bpf_disabled', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'kernel.yama.ptrace_scope', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv4.conf.all.accept_redirects', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv4.conf.all.accept_source_route', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv4.conf.all.log_martians', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv4.conf.all.rp_filter', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv4.conf.all.send_redirects', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv4.icmp_echo_ignore_broadcasts', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv4.ip_forward', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv4.tcp_syncookies', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv6.conf.all.accept_ra', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv6.conf.all.accept_redirects', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'net.ipv6.conf.all.disable_ipv6', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'vm.mmap_min_addr', 'system'),
  ('allow_value', 'sysctl', 'key', 'any', 'vm.swappiness', 'system');

-- ---------------------------------------------------------------------------
-- Paquets gérables
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO gpo_restriction (kind, module_type, field_name, scope, value, updated_by) VALUES
  ('allow_value', 'package', 'package', 'any', 'aide', 'system'),
  ('allow_value', 'package', 'package', 'any', 'auditd', 'system'),
  ('allow_value', 'package', 'package', 'any', 'chrony', 'system'),
  ('allow_value', 'package', 'package', 'any', 'cups', 'system'),
  ('allow_value', 'package', 'package', 'any', 'curl', 'system'),
  ('allow_value', 'package', 'package', 'any', 'fail2ban', 'system'),
  ('allow_value', 'package', 'package', 'any', 'git', 'system'),
  ('allow_value', 'package', 'package', 'any', 'htop', 'system'),
  ('allow_value', 'package', 'package', 'any', 'nftables', 'system'),
  ('allow_value', 'package', 'package', 'any', 'rsh-client', 'system'),
  ('allow_value', 'package', 'package', 'any', 'rsync', 'system'),
  ('allow_value', 'package', 'package', 'any', 'telnet', 'system'),
  ('allow_value', 'package', 'package', 'any', 'tmux', 'system'),
  ('allow_value', 'package', 'package', 'any', 'unzip', 'system'),
  ('allow_value', 'package', 'package', 'any', 'vim', 'system'),
  ('allow_value', 'package', 'package', 'any', 'vsftpd', 'system'),
  ('allow_value', 'package', 'package', 'any', 'xinetd', 'system'),
  ('allow_value', 'package', 'package', 'any', 'zsh', 'system');

-- ---------------------------------------------------------------------------
-- Tâches planifiables en scope utilisateur
--
-- Ces identifiants réfèrent à des commandes implémentées côté agent client.
-- En ajouter un ici sans implémentation donnera une tâche sans effet.
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO gpo_restriction (kind, module_type, field_name, scope, value, note, updated_by) VALUES
  ('allow_value', 'user_cron', 'command_id', 'any', 'backup_home', 'sauvegarde du home', 'system'),
  ('allow_value', 'user_cron', 'command_id', 'any', 'cleanup_tmp', 'purge des fichiers temporaires', 'system'),
  ('allow_value', 'user_cron', 'command_id', 'any', 'report_disk_usage', 'rapport d occupation disque', 'system'),
  ('allow_value', 'user_cron', 'command_id', 'any', 'sync_dotfiles', 'synchronisation des fichiers de configuration', 'system'),
  ('allow_value', 'user_cron', 'command_id', 'any', 'rotate_user_logs', 'rotation des journaux utilisateur', 'system');

-- ---------------------------------------------------------------------------
-- Jeux de commandes sudo (définitions à contenu)
--
-- Le nom sert de valeur dans la GPO, le contenu est ce que l'agent rend dans
-- /etc/sudoers.d/. Une commande par ligne ; ALL seul autorise tout.
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO gpo_value_definition (module_type, field_name, name, payload_kind, payload, note, updated_by) VALUES
  ('sudoers_rule', 'command_set', 'ALL', 'command_list',
   'ALL',
   'toutes les commandes - equivalent a un acces root complet', 'system'),

  ('sudoers_rule', 'command_set', 'pkg_management', 'command_list',
   '/usr/bin/apt-get\n/usr/bin/apt\n/usr/bin/dnf\n/usr/bin/yum\n/usr/bin/rpm\n/usr/bin/dpkg',
   'installation et mise a jour de paquets', 'system'),

  ('sudoers_rule', 'command_set', 'service_control', 'command_list',
   '/usr/bin/systemctl start\n/usr/bin/systemctl stop\n/usr/bin/systemctl restart\n/usr/bin/systemctl reload\n/usr/bin/systemctl status',
   'pilotage des services systemd', 'system'),

  ('sudoers_rule', 'command_set', 'network_diagnostics', 'command_list',
   '/usr/bin/ping\n/usr/sbin/ip\n/usr/bin/ss\n/usr/sbin/tcpdump\n/usr/bin/traceroute\n/usr/bin/dig',
   'diagnostic reseau', 'system'),

  ('sudoers_rule', 'command_set', 'log_read', 'command_list',
   '/usr/bin/journalctl\n/usr/bin/dmesg\n/usr/bin/tail\n/usr/bin/less',
   'lecture des journaux systeme', 'system'),

  ('sudoers_rule', 'command_set', 'disk_read', 'command_list',
   '/usr/bin/df\n/usr/bin/du\n/usr/sbin/blkid\n/usr/bin/lsblk\n/usr/bin/smartctl',
   'inspection du stockage', 'system');

-- ---------------------------------------------------------------------------
-- Emplacements de fichiers refusés dans TOUS les scopes
--
-- Ce sont les fichiers qui gouvernent eux-mêmes les privilèges, plus l'état
-- local de l'agent Vaultaire.
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO gpo_restriction (kind, scope, value, note, updated_by) VALUES
  ('path_deny', 'any', '/etc/pam.d/',            'pile d authentification : modifiable = contournement de l auth', 'system'),
  ('path_deny', 'any', '/etc/security/',         'configuration PAM (pwquality, faillock, limits)', 'system'),
  ('path_deny', 'any', '/etc/sudoers',           'elevation de privilege directe', 'system'),
  ('path_deny', 'any', '/etc/sudoers.d/',        'elevation de privilege directe', 'system'),
  ('path_deny', 'any', '/etc/shadow',            'empreintes de mots de passe locaux', 'system'),
  ('path_deny', 'any', '/etc/gshadow',           'empreintes de mots de passe de groupes', 'system'),
  ('path_deny', 'any', '/etc/passwd',            'comptes locaux et shells', 'system'),
  ('path_deny', 'any', '/etc/group',             'appartenances de groupes locaux', 'system'),
  ('path_deny', 'any', '/etc/ssh/sshd_config',   'fichier principal sshd : utilisez le module ssh_server_config', 'system'),
  ('path_deny', 'any', '/etc/ssh/ssh_host_',     'cles d hote du serveur SSH', 'system'),
  ('path_deny', 'any', '/etc/vaultaire/',        'configuration de l agent Vaultaire', 'system'),
  ('path_deny', 'any', '/var/lib/vaultaire/',    'etat local de l agent (versions de GPO appliquees)', 'system'),
  ('path_deny', 'any', '/lib/security/',         'modules PAM', 'system'),
  ('path_deny', 'any', '/lib64/security/',       'modules PAM', 'system'),
  ('path_deny', 'any', '/usr/lib/security/',     'modules PAM', 'system'),
  ('path_deny', 'any', '/usr/lib64/security/',   'modules PAM', 'system'),
  ('path_deny', 'any', '/root/.ssh/',            'acces SSH du compte root', 'system');

-- ---------------------------------------------------------------------------
-- Emplacements refusés au scope utilisateur uniquement
--
-- Deux familles : ce qui est system-wide (relève du scope machine), et à
-- l'intérieur du home les fichiers qui gouvernent l'accès au compte ou son
-- environnement de connexion.
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO gpo_restriction (kind, scope, value, note, updated_by) VALUES
  ('path_deny', 'user', '/etc/',   'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/usr/',   'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/bin/',   'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/sbin/',  'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/lib/',   'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/lib64/', 'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/boot/',  'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/dev/',   'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/proc/',  'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/sys/',   'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/var/',   'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/opt/',   'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/srv/',   'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/run/',   'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/root/',  'hors du home : releve du scope machine', 'system'),
  ('path_deny', 'user', '/%h/.ssh/',            'un acces SSH permanent au compte', 'system'),
  ('path_deny', 'user', '/%h/.profile',         'execute a chaque ouverture de session', 'system'),
  ('path_deny', 'user', '/%h/.bash_profile',    'execute a chaque ouverture de session', 'system'),
  ('path_deny', 'user', '/%h/.bash_login',      'execute a chaque ouverture de session', 'system'),
  ('path_deny', 'user', '/%h/.bashrc',          'execute a chaque shell interactif', 'system'),
  ('path_deny', 'user', '/%h/.zshrc',           'execute a chaque shell interactif', 'system'),
  ('path_deny', 'user', '/%h/.zprofile',        'execute a chaque ouverture de session', 'system'),
  ('path_deny', 'user', '/%h/.pam_environment', 'environnement applique par PAM', 'system');

-- ---------------------------------------------------------------------------
-- Emplacement autorisé au scope utilisateur
--
-- La présence d'au moins une autorisation transforme la validation en liste
-- blanche pour ce scope : tout chemin hors de ce préfixe est refusé.
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO gpo_restriction (kind, scope, value, note, updated_by) VALUES
  ('path_allow', 'user', '/%h/', 'zone d ecriture des GPO utilisateur', 'system');

-- ---------------------------------------------------------------------------
-- Variables d'environnement interdites
--
-- Toutes permettent de détourner l'exécution d'un binaire quelconque.
-- ---------------------------------------------------------------------------

INSERT IGNORE INTO gpo_restriction (kind, scope, value, note, updated_by) VALUES
  ('env_deny', 'any', 'LD_PRELOAD',         'injection de bibliotheque partagee', 'system'),
  ('env_deny', 'any', 'LD_LIBRARY_PATH',    'substitution de bibliotheque', 'system'),
  ('env_deny', 'any', 'LD_AUDIT',           'injection via l interface d audit du loader', 'system'),
  ('env_deny', 'any', 'LD_ASSUME_KERNEL',   'contournement de version de la glibc', 'system'),
  ('env_deny', 'any', 'GCONV_PATH',         'chargement de modules de conversion arbitraires', 'system'),
  ('env_deny', 'any', 'PATH',               'substitution de commandes', 'system'),
  ('env_deny', 'any', 'IFS',                'decoupage de mots dans le shell', 'system'),
  ('env_deny', 'any', 'BASH_ENV',           'script execute au demarrage de bash non interactif', 'system'),
  ('env_deny', 'any', 'ENV',                'equivalent BASH_ENV pour sh', 'system'),
  ('env_deny', 'any', 'SHELL',              'changement d interpreteur', 'system'),
  ('env_deny', 'any', 'PROMPT_COMMAND',     'commande executee a chaque invite', 'system'),
  ('env_deny', 'any', 'PYTHONPATH',         'substitution de module Python', 'system'),
  ('env_deny', 'any', 'PYTHONSTARTUP',      'script execute au lancement de l interpreteur', 'system'),
  ('env_deny', 'any', 'PERL5LIB',           'substitution de module Perl', 'system'),
  ('env_deny', 'any', 'NODE_OPTIONS',       'injection d options au demarrage de Node', 'system'),
  ('env_deny', 'any', 'GIT_SSH',            'commande SSH utilisee par git', 'system'),
  ('env_deny', 'any', 'GIT_SSH_COMMAND',    'commande SSH utilisee par git', 'system'),
  ('env_deny', 'any', 'SSH_ASKPASS',        'programme de saisie de mot de passe', 'system'),
  ('env_deny', 'any', 'SUDO_ASKPASS',       'programme de saisie de mot de passe sudo', 'system'),
  ('env_deny', 'any', 'HOSTALIASES',        'detournement de la resolution de noms', 'system'),
  ('env_deny', 'any', 'NSS_WRAPPER_PASSWD', 'detournement de la base de comptes', 'system');


-- ---------------------------------------------------------------------------
-- Modules noyau interdictibles
-- ---------------------------------------------------------------------------
-- Stockage amovible et protocoles rarement utilises : les vecteurs classiques
-- d'exfiltration ou de surface d'attaque inutile. Aucun n'est necessaire au
-- fonctionnement d'un poste de travail ou d'un serveur standard.

INSERT IGNORE INTO gpo_restriction (kind, module_type, field_name, scope, value, updated_by) VALUES
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'usb-storage', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'firewire-core', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'thunderbolt', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'cramfs', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'freevxfs', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'jffs2', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'hfs', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'hfsplus', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'udf', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'dccp', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'sctp', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'rds', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'tipc', 'system'),
  ('allow_value', 'kernel_module_policy', 'module', 'any', 'bluetooth', 'system');

-- ---------------------------------------------------------------------------
-- Shells attribuables
-- ---------------------------------------------------------------------------
-- nologin interdit la connexion interactive tout en laissant les services
-- fonctionner sous ce compte. rbash est un shell restreint : pas de cd, pas de
-- redirection, pas d'execution par chemin absolu.

INSERT IGNORE INTO gpo_restriction (kind, module_type, field_name, scope, value, updated_by) VALUES
  ('allow_value', 'user_shell', 'shell', 'user', '/bin/bash', 'system'),
  ('allow_value', 'user_shell', 'shell', 'user', '/bin/sh', 'system'),
  ('allow_value', 'user_shell', 'shell', 'user', '/bin/rbash', 'system'),
  ('allow_value', 'user_shell', 'shell', 'user', '/usr/bin/zsh', 'system'),
  ('allow_value', 'user_shell', 'shell', 'user', '/usr/sbin/nologin', 'system'),
  ('allow_value', 'user_shell', 'shell', 'user', '/sbin/nologin', 'system');

-- ---------------------------------------------------------------------------
-- Groupes locaux attribuables
-- ---------------------------------------------------------------------------
-- ATTENTION : cette liste est un point d'elevation de privileges.
--
-- Volontairement limitee a des groupes de PERIPHERIQUES, sans consequence sur
-- les privileges. Sont deliberement ABSENTS : docker, lxd, kvm, libvirt, disk,
-- adm, shadow, sudo, wheel. Chacun permet, directement ou non, de lire ou
-- modifier n'importe quel fichier de la machine — appartenir a docker revient
-- a etre root, puisqu'on peut monter / dans un conteneur.
--
-- Les ajouter reste possible depuis l'interface, mais c'est alors une decision
-- explicite d'un membre du groupe vaultaire, pas un defaut livre.

INSERT IGNORE INTO gpo_restriction (kind, module_type, field_name, scope, value, updated_by) VALUES
  ('allow_value', 'user_group_membership', 'group', 'user', 'audio', 'system'),
  ('allow_value', 'user_group_membership', 'group', 'user', 'video', 'system'),
  ('allow_value', 'user_group_membership', 'group', 'user', 'plugdev', 'system'),
  ('allow_value', 'user_group_membership', 'group', 'user', 'dialout', 'system'),
  ('allow_value', 'user_group_membership', 'group', 'user', 'lp', 'system'),
  ('allow_value', 'user_group_membership', 'group', 'user', 'scanner', 'system'),
  ('allow_value', 'user_group_membership', 'group', 'user', 'cdrom', 'system');
