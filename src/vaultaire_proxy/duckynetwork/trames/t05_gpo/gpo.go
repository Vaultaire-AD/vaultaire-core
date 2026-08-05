// Package gpo traite la catégorie 05 : transport des politiques.
//
// # Ce dossier est un SQUELETTE, et c'est volontaire
//
// Les GPO ne concernent que les machines du parc : elles décrivent une
// configuration à appliquer sur un système. Un service n'en reçoit pas.
//
// Particularité à connaître avant d'implémenter : les réponses 05 sont
// ASYNCHRONES côté agent. Le paquet gpo réveille un cycle en attente et enchaîne
// lui-même ses demandes de fragments, au lieu de répondre dans le fil du
// Spliter. Un traitement synchrone ici bloquerait la boucle de réception pendant
// tout le transfert.
package gpo

import (
	"vaultaire_proxy/duckynetwork/logs"
	"vaultaire_proxy/duckynetwork/storage"
)

// Codes de la catégorie.
const (
	AskMachine     = "05_01"
	MachineManif   = "05_02"
	MachineNoop    = "05_03"
	MachineError   = "05_04"
	AskUser        = "05_05"
	UserManif      = "05_06"
	AskChunk       = "05_09"
	Chunk          = "05_10"
	ChunkError     = "05_11"
	ApplyReport    = "05_12"
	ApplyReportAck = "05_13"
)

// Handler journalise et ne répond rien.
func Handler(trames storage.Trames_struct_client, session *storage.DuckySession) string {
	logs.Write("DEBUG", "trame 05 reçue, aucun traitement branché : "+trames.Code())
	return ""
}
