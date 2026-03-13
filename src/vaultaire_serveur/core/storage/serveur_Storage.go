package storage

type Is_Serveur_Online struct {
	Client_ID           string
	Username            string
	Duckysession        *DuckySession
	Failed_Time         int
	SessionIntegritykey string
}

var Serveur_Online []Is_Serveur_Online
