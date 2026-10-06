//go:build windows

package ipc

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/sys/windows"
)

// Demander ouvre le tube, pose une requête, lit la réponse et referme.
//
// C'est le pendant Go de ce que fait la DLL C++ du Credential Provider. Il sert
// à l'outil `vaultaire_login.exe` — et c'est volontaire : la chaîne complète
// (tube, protocole, core, provisionnement) s'éprouve ainsi sans écran de
// connexion, donc sans risquer la machine de test.
func Demander(req Requete, delai time.Duration) (Reponse, error) {
	nom, err := windows.UTF16PtrFromString(NomTube)
	if err != nil {
		return Reponse{}, err
	}

	// WaitNamedPipe : toutes les instances peuvent être occupées par d'autres
	// sessions. Attendre vaut mieux qu'échouer — l'écran de connexion n'a pas
	// de bouton « réessayer ».
	fin := time.Now().Add(delai)
	var tube windows.Handle
	for {
		tube, err = windows.CreateFile(nom,
			windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			break
		}
		if err != windows.ERROR_PIPE_BUSY || time.Now().After(fin) {
			return Reponse{}, fmt.Errorf("canal de l'agent injoignable (%s) : %w", NomTube, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer func() { _ = windows.CloseHandle(tube) }()

	conn := &connexionTube{tube: tube, fin: fin}
	donnees, err := json.Marshal(req)
	if err != nil {
		return Reponse{}, err
	}
	if _, err := conn.Write(append(donnees, '\n')); err != nil {
		return Reponse{}, fmt.Errorf("requête non transmise : %w", err)
	}

	var rep Reponse
	if err := json.NewDecoder(io.LimitReader(conn, TailleMaxRequete)).Decode(&rep); err != nil {
		return Reponse{}, fmt.Errorf("réponse illisible : %w", err)
	}
	return rep, nil
}
