package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

func AddSSHKeyToClient(user, host string) error {
	pubKeyPath := os.Getenv("VAULTAIRE_pubKeyLogin")
	if pubKeyPath == "" {
		return fmt.Errorf("❌ Variable d’environnement VAULTAIRE_pubKeyLogin non définie")
	}
	fmt.Printf("📁 Clé publique : %s\n", pubKeyPath)
	fmt.Printf("📡 Tentative d’envoi de la clé publique à %s@%s\n", user, host)
	cmd := exec.Command("ssh-copy-id", "-f", "-i", pubKeyPath, fmt.Sprintf("%s@%s", user, host))

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("❌ Échec de ssh-copy-id : %v\n%s", err, stderr.String())
	}

	fmt.Println("✅ Clé publique ajoutée avec succès.")
	return nil
}

// cheminSocket est le socket d'administration du serveur.
//
// VAULTAIRE_SOCKET le remplace : le chemin était écrit en dur à deux endroits,
// et une installation ailleurs qu'en /opt obligeait à recompiler.
func cheminSocket() string {
	if p := os.Getenv("VAULTAIRE_SOCKET"); p != "" {
		return p
	}
	return "/opt/vaultaire/vaultaire.sock"
}

// envoyerCommande envoie une commande et rend la réponse complète.
//
// Un SEUL chemin pour les deux modes — argument et invite interactive. Ils
// avaient chacun le leur, et ils ne lisaient pas pareil : le mode argument
// jusqu'à la fin, l'invite un unique Read de 1024 octets. La même commande
// rendait donc deux sorties différentes selon la façon dont on la tapait.
//
// La connexion est fermée AVANT le retour, et non par un defer : dans l'invite,
// le defer était posé à l'intérieur de la boucle, donc exécuté à la sortie du
// programme et non à chaque tour. Les descripteurs s'accumulaient pour toute la
// durée de la session.
func envoyerCommande(command string) string {
	conn, err := net.Dial("unix", cheminSocket())
	if err != nil {
		return "Erreur connexion serveur: " + err.Error()
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("error closing connection: %v", err)
		}
	}()

	if _, err := conn.Write([]byte(command)); err != nil {
		return "Erreur envoi commande: " + err.Error()
	}

	response, err := readFullResponse(conn)
	if err != nil {
		return "Erreur lecture réponse: " + err.Error()
	}

	// Une réponse vide est SIGNALÉE plutôt qu'affichée comme une ligne blanche.
	//
	// Le serveur écrit toujours quelque chose : un silence signifie qu'il a
	// fermé la connexion sans répondre — une panique dans le traitement, par
	// exemple. Une ligne vide laissait croire que la commande n'avait rien
	// fait, alors que l'écriture en base avait pu aboutir avant l'incident.
	if strings.TrimSpace(response) == "" {
		return "Aucune réponse du serveur : la connexion s'est fermée sans réponse. " +
			"L'opération a pu aboutir malgré tout — vérifiez avec « get », et " +
			"consultez le journal du serveur."
	}
	return strings.TrimSpace(response)
}

func readFullResponse(conn net.Conn) (string, error) {
	var result strings.Builder
	buf := make([]byte, 1024)

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				// Fin normale de la lecture
				break
			}
			return "", err
		}
	}
	return result.String(), nil
}

func main() {
	// Vérifier si des arguments ont été passés
	if len(os.Args) > 1 {
		// Joindre les arguments en une seule chaîne de caractères
		command := strings.Join(os.Args[1:], " ")
		if strings.Contains(command, "-join") {
			parts := strings.Fields(command)
			for i := 0; i < len(parts)-2; i++ {
				if parts[i] == "-join" {
					ip := parts[i+1]
					username := parts[i+2]

					fmt.Println("🔑 Détection de -join avec IP:", ip, "et utilisateur:", username)
					if err := AddSSHKeyToClient(username, ip); err != nil {
						fmt.Println(err)
					} else {
						fmt.Println("🔑 Clé SSH ajoutée avec succès.")
					}
					break
				}
			}
		}
		fmt.Println(envoyerCommande(command))
	} else {
		// Si aucun argument n'est fourni, démarrer le mode interactif
		reader := bufio.NewReader(os.Stdin)

		for {
			fmt.Print("vaultaire> ")
			input, _ := reader.ReadString('\n')
			command := strings.TrimSpace(input)

			if command == "exit" {
				fmt.Println("Fermeture de Vaultaire CLI...")
				break
			}
			if strings.Contains(command, "-join") {
				parts := strings.Fields(command)
				for i := 0; i < len(parts)-2; i++ {
					if parts[i] == "-join" {
						ip := parts[i+1]
						username := parts[i+2]

						fmt.Println("🔑 Détection de -join avec IP:", ip, "et utilisateur:", username)
						// Le `else` manquait ici, et seulement ici : l'invite
						// annonçait « Clé SSH ajoutée avec succès » juste après
						// avoir affiché l'erreur qui disait le contraire. Le
						// mode argument, lui, l'avait.
						if err := AddSSHKeyToClient(username, ip); err != nil {
							fmt.Println(err)
						} else {
							fmt.Println("🔑 Clé SSH ajoutée avec succès.")
						}
						break
					}
				}
			}

			// Le mode interactif lit la réponse EXACTEMENT comme le mode
			// argument, et c'est le point de ce bloc.
			//
			// Il ne le faisait pas : un seul `conn.Read` dans un tampon de 1024
			// octets. Toute réponse plus longue était coupée, sans un mot —
			// « get -p -u <nom> » dépasse largement ce seuil dès qu'une
			// permission porte quelques droits, et « eyes » ou « get -u »
			// aussi. La MÊME commande rendait donc deux sorties différentes
			// selon qu'on la tapait dans l'invite ou en argument, et celle de
			// l'invite paraissait simplement incomplète.
			//
			// Pire qu'une troncature : sur un socket, un seul Read ne garantit
			// même pas de recevoir le premier morceau entier. Une réponse
			// courte pouvait revenir amputée de façon intermittente.
			fmt.Println(envoyerCommande(command))
		}
	}
}
