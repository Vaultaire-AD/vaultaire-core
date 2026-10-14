package pamcommunication

// Le motif d'un refus, présenté à la personne — TO-DO 171.
//
// # La règle, et son exception
//
// Sur un refus, le module PAM ne dit RIEN de plus que « refusé ». C'est voulu
// (TO-DO 99) : un message qui varierait après un mot de passe faux apprendrait à
// qui essaie des mots de passe qu'un compte existe, ou qu'il a trouvé le bon.
//
// Deux motifs du core échappent à cette objection. Il ne les rend qu'APRÈS un
// mot de passe prouvé (ssh_client.go, SSH_SEND_Pubkey_AUTH) : qui les lit
// connaît déjà le mot de passe du compte, et ne lui apprend donc rien. Les taire
// avait un coût réel : la personne retapait son mot de passe, échouait encore,
// et appelait le support — pour un mot de passe expiré qu'elle pouvait changer
// seule sur le portail.
//
// # Une liste FERMÉE
//
// Seuls ces deux motifs passent, comparés au texte exact du core. Tout autre
// refus — « permission denied », « mfa unavailable », un motif inconnu d'un
// core plus récent, une chaîne vide — reste muet. Le texte affiché est composé
// ICI, jamais recopié du core : un core compromis ou un motif mal formé ne
// pourrait faire afficher que l'une de ces deux phrases.
//
// « mfa unavailable » vient lui aussi après le mot de passe, mais il décrit une
// panne du core, pas une action possible pour la personne : il reste au journal.
var motifsAffichables = map[string]string{
	"password expired": "Votre mot de passe a expiré. Changez-le sur le portail Vaultaire, puis reconnectez-vous.",
	"mfa required": "Ce compte demande un code de second facteur : saisissez le code à 6 chiffres " +
		"de votre application d'authentification (0000 ne suffit pas).",
}

// MessageDeRefus rend le texte à présenter pour un motif de refus du core, ou
// "" si ce motif doit rester muet.
func MessageDeRefus(motif string) string {
	return motifsAffichables[motif]
}
