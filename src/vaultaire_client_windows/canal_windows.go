//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"

	"duckynetworkclient/V1/duckynetwork/logs"

	"vaultaire_client_windows/auth"
	"vaultaire_client_windows/ipc"
)

// NomService est le nom du service Windows, celui qu'attend install.ps1.
const NomService = "VaultaireAgent"

// servir ouvre le canal du Credential Provider et ne rend plus la main.
//
// # Service ou console : la même chose, deux enveloppes
//
// Windows démarre un service en lui parlant par un canal de contrôle ; un
// binaire qui ne répond pas à ce canal est tué au bout de trente secondes,
// « le service n'a pas répondu à temps ». Mais le MÊME binaire lancé à la main
// pour un diagnostic n'a pas ce canal. svc.IsWindowsService fait la différence,
// et le corps de l'agent est identique dans les deux cas.
func servir(forcerConsole bool) {
	serveur := ipc.NouveauServeur(auth.Traiter)
	bilan(serveur.Stats)

	estService := false
	if !forcerConsole {
		var err error
		estService, err = svc.IsWindowsService()
		if err != nil {
			logs.Write_log("WARNING", "mode de lancement indéterminé, console supposée : "+err.Error())
		}
	}

	if !estService {
		logs.Write_log("INFO", "agent lancé en console (Ctrl+C pour arrêter)")
		if err := serveur.Servir(); err != nil {
			fmt.Fprintln(os.Stderr, "vaultaire :", err)
			logs.Write_log("CRITICAL", "canal arrêté : "+err.Error())
			os.Exit(1)
		}
		return
	}

	if err := svc.Run(NomService, &serviceWindows{canal: serveur}); err != nil {
		logs.Write_log("CRITICAL", "service arrêté : "+err.Error())
		os.Exit(1)
	}
}

// serviceWindows répond au gestionnaire de services.
type serviceWindows struct{ canal *ipc.Serveur }

func (s *serviceWindows) Execute(_ []string, requetes <-chan svc.ChangeRequest, etat chan<- svc.Status) (bool, uint32) {
	const accepte = svc.AcceptStop | svc.AcceptShutdown

	etat <- svc.Status{State: svc.StartPending}
	fini := make(chan error, 1)
	logs.Go("canal du Credential Provider", func() { fini <- s.canal.Servir() })
	etat <- svc.Status{State: svc.Running, Accepts: accepte}

	for {
		select {
		case err := <-fini:
			// Le canal ne doit jamais s'arrêter seul : sans lui, l'écran de
			// connexion n'a plus personne à qui demander un verdict. On rend la
			// main au gestionnaire de services, à lui de redémarrer le service.
			if err != nil {
				logs.Write_log("CRITICAL", "canal arrêté : "+err.Error())
			}
			etat <- svc.Status{State: svc.StopPending}
			return false, 1

		case r := <-requetes:
			switch r.Cmd {
			case svc.Interrogate:
				etat <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				servies, refusees := s.canal.Stats()
				logs.Write_log("INFO", fmt.Sprintf(
					"arrêt demandé : %d requête(s) servie(s), %d refusée(s)", servies, refusees))
				etat <- svc.Status{State: svc.StopPending}
				s.canal.Arreter()
				return false, 0
			default:
				logs.Write_log("DEBUG", fmt.Sprintf("commande de service %d ignorée", r.Cmd))
			}
		}
	}
}
