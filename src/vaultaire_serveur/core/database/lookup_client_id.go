package database

// LookupClientID résout un computeur_id en id_logiciel.
//
// LIMIT 1 : computeur_id n'est pas déclaré unique dans le schéma. Sans la
// limite, un doublon accidentel ferait échouer la lecture au lieu d'en
// désigner un — comportement déjà retenu par Get_ClientID_By_ComputerID.
func LookupClientID(q RowQuerier, computerID string) (int, bool, error) {
	return lookup(q, `SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ? LIMIT 1`, computerID)
}
