package sshauth

import (
	"duckynetworkclient/V1/duckynetwork/storage"
)

// HandleTrameSSH branche la catégorie 03 sur le registre du socle.
//
// # Pourquoi un adaptateur plutôt qu'un changement de signature
//
// Le socle appelle ses gestionnaires avec `(trame, session)`, parce que la
// plupart ont besoin de la session — clé de chiffrement, identifiant, état.
// SSH_Auth_Manager, lui, n'a besoin que de la connexion.
//
// Changer sa signature pour coller au registre lui donnerait accès à toute la
// session sans qu'il en fasse rien, et rendrait plus difficile de voir ce dont
// il dépend réellement. L'adaptateur coûte trois lignes et garde cette limite
// visible.
func HandleTrameSSH(trames storage.Trames_struct_client, session *storage.DuckySession) string {
	return SSH_Auth_Manager(trames, session.Conn)
}
