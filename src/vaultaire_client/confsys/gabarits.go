package confsys

// Les gabarits — EXTRAITS de rocky.sh et debian.sh, octet pour octet.
//
// Les scripts d'installation restent ce qui écrit la configuration à
// l'installation ; l'agent la tient ensuite à jour avec SA version. Les deux
// doivent produire les mêmes octets : TestLesScriptsEtLAgentProduisentLaMemeChose
// joue chaque script à blanc et compare. Changer un gabarit, c'est changer les
// deux, ET monter la version de la règle (regles.go).

// MarquePAM : le marqueur de version d'un fichier tenu en entier, ou d'une
// pile Debian branchée. « v1 » : voir VersionPAM.
const MarquePAM = "# vaultaire-conf v1 - tenu par l'agent Vaultaire : ne pas modifier a la main"

// Les piles de Rocky, écrites en entier (rocky.sh, étape 5).
const (
	pileLoginRocky = `#%PAM-1.0
# vaultaire-conf v1 - tenu par l'agent Vaultaire : ne pas modifier a la main
auth        [success=done ignore=ignore default=die]    pam_login_custom_module.so
auth        substack       system-auth
auth        include        postlogin

account     required       pam_nologin.so
account     include        system-auth

password    include        system-auth

session     required       pam_selinux.so close
session     required       pam_loginuid.so
session     required       pam_selinux.so open
session     required       pam_logout_custom_module.so
session     required       pam_namespace.so
session     optional       pam_keyinit.so force revoke
session     include        system-auth
session     include        postlogin
-session    optional       pam_ck_connector.so
`

	pileSSHDRocky = `#%PAM-1.0
# vaultaire-conf v1 - tenu par l'agent Vaultaire : ne pas modifier a la main
auth        [success=done ignore=ignore default=die]    pam_ssh_auth_module.so
auth        substack       password-auth
auth        include        postlogin

account     required       pam_nologin.so
account     include        password-auth

session     required       pam_selinux.so close
session     required       pam_loginuid.so
session     required       pam_selinux.so open env_params
session     required       pam_namespace.so
session     optional       pam_keyinit.so force revoke
session     optional       pam_motd.so
session     include        password-auth
session     include        postlogin
`

	pileGDMRocky = `#%PAM-1.0
# vaultaire-conf v1 - tenu par l'agent Vaultaire : ne pas modifier a la main
auth        [success=done ignore=ignore default=bad]    pam_login_custom_module.so
auth        [success=done ignore=ignore default=bad]    pam_selinux_permit.so
auth        substack       password-auth
auth        optional       pam_gnome_keyring.so
auth        include        postlogin

account     required       pam_nologin.so
account     include        password-auth

password    substack       password-auth
-password   optional       pam_gnome_keyring.so use_authtok

session     required       pam_selinux.so close
session     required       pam_loginuid.so
session     optional       pam_console.so
-session    optional       pam_ck_connector.so
session     required       pam_selinux.so open
session     required       pam_logout_custom_module.so
session     optional       pam_keyinit.so force revoke
session     required       pam_namespace.so
session     include        password-auth
session     optional       pam_gnome_keyring.so auto_start
session     include        postlogin
`
)

// Les lignes branchées dans les piles de Debian (debian.sh, étape 5).
const (
	authLoginDebian = "auth    [success=done ignore=ignore default=die]    pam_login_custom_module.so"
	authSSHDDebian  = "auth    [success=done ignore=ignore default=die]    pam_ssh_auth_module.so"
	authGDMDebian   = "auth    [success=done ignore=ignore default=bad]    pam_login_custom_module.so"
	sessionDebian   = "session required    pam_logout_custom_module.so"
)

// blocSSHD : ajouté en fin de sshd_config, entre ses deux marqueurs (étape 7
// des deux scripts).
const blocSSHD = `# vaultaire-conf v1 - debut du bloc Vaultaire : ne pas modifier a la main
UsePAM yes
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
AuthorizedKeysCommand /usr/bin/vaultaire_client --fetch-key %u
AuthorizedKeysCommandUser root
Include /etc/ssh/sshd_config.d/*.conf
# vaultaire-conf - fin du bloc Vaultaire
`

// directivesSSHD : retirées de sshd_config avant d'y ajouter le bloc — les
// mêmes que la boucle « for directive in … » des scripts, et avec la même
// règle : toute ligne qui COMMENCE par l'une d'elles.
var directivesSSHD = []string{"UsePAM", "KbdInteractiveAuthentication", "ChallengeResponseAuthentication", "AuthenticationMethods", "PubkeyAuthentication", "Include", "AuthorizedKeysCommand", "AuthorizedKeysCommandUser"}

// dconfGDM : la liste des comptes masquée sur l'écran de connexion.
const dconfGDM = `# vaultaire-conf v1 - tenu par l'agent Vaultaire : ne pas modifier a la main
[org/gnome/login-screen]
disable-user-list=true
`
