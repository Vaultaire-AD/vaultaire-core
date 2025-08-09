package autoaddclientgo

import (
	"DUCKY/serveur/storage"
	"bufio"
	"os"
	"strings"
)

// Charge chaque ligne non vide et non commentée d’un fichier bash dans AutoAddClientCommandesList
func LoadCommandsFromShellScript(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	storage.AutoAddClientCommandesList = storage.AutoAddClientCommandesList[:0] // reset liste

	scanner := bufio.NewScanner(file)
	var inHereDoc bool
	var hereDocEndMarker string
	var currentBlock strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		if inHereDoc {
			currentBlock.WriteString(line + "\n")
			if line == hereDocEndMarker {
				// Fin du here-doc
				storage.AutoAddClientCommandesList = append(storage.AutoAddClientCommandesList, currentBlock.String())
				inHereDoc = false
			}
			continue
		}

		// Recherche début here-doc
		if strings.HasPrefix(line, "cat ") && strings.Contains(line, "<<") {
			// Extraire le marqueur EOF (ex: EOF ou 'EOF')
			hereDocEndMarker = "EOF" // ou autre, selon le marqueur dans la ligne
			inHereDoc = true
			currentBlock.Reset()
			currentBlock.WriteString(line + "\n")
			continue
		}

		// Sinon ligne normale
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		storage.AutoAddClientCommandesList = append(storage.AutoAddClientCommandesList, line)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
