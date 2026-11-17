package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"vaultaire/core/storage"
)

// Description OpenAPI 3.0 de l'API REST — TO-DO 270.
//
// GÉNÉRÉE de la table des routes et du registre, jamais écrite à la main : une
// description tenue à côté du code finit par décrire une autre API. Servie
// sans authentification (GET /api/v1/openapi.json) : elle ne contient que des
// noms de routes et d'actions, et c'est ce qu'un outil (Swagger UI, un
// générateur de client) lit avant d'avoir des identifiants.

func servirOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(DescriptionOpenAPI())
}

// DescriptionOpenAPI rend le document. Exportée pour les tests et pour
// `vlt api --openapi`.
func DescriptionOpenAPI() map[string]any {
	chemins := map[string]map[string]any{}
	ajouter := func(methode, chemin string, op map[string]any) {
		if chemins[chemin] == nil {
			chemins[chemin] = map[string]any{}
		}
		chemins[chemin][strings.ToLower(methode)] = op
	}

	for _, rt := range routesREST {
		statut := rt.Statut
		if statut == 0 {
			statut = http.StatusOK
		}
		op := operation(rt.Action, rt.Resume, rt.Tag, statut, parametresDeChemin(rt.Chemin))
		if rt.Methode != http.MethodGet && rt.Methode != http.MethodDelete {
			op["requestBody"] = corpsParametres()
		}
		ajouter(rt.Methode, prefixeREST+rt.Chemin, op)
	}

	ajouter("GET", prefixeREST+"/actions", map[string]any{
		"tags": []string{"actions"}, "operationId": "catalogue",
		"summary":   "catalogue des actions du registre : nom, droit exigé, méthode à employer",
		"responses": reponses(http.StatusOK),
	})
	gen := parametresDeChemin("/actions/{action}")
	opGet := operation("", "exécute une action de LECTURE du registre ; paramètres en requête", "actions", http.StatusOK, gen)
	opGet["operationId"] = "action_lecture"
	opPost := operation("", "exécute n'importe quelle action du registre ; paramètres dans le corps", "actions", http.StatusOK, gen)
	opPost["operationId"] = "action"
	opPost["requestBody"] = corpsParametres()
	ajouter("GET", prefixeREST+"/actions/{action}", opGet)
	ajouter("POST", prefixeREST+"/actions/{action}", opPost)

	cmd := operation("", "exécute une ligne de commande vlt ; la sortie texte est dans data.output", "command", http.StatusOK, nil)
	cmd["operationId"] = "command"
	cmd["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{
		"schema": map[string]any{"type": "object", "required": []string{"command"},
			"properties": map[string]any{"command": map[string]any{"type": "string", "example": "status -c"}}},
	}}}
	ajouter("POST", prefixeREST+"/command", cmd)

	// Ordre stable : un document qui change d'ordre d'un appel à l'autre se
	// compare mal.
	noms := make([]string, 0, len(chemins))
	for c := range chemins {
		noms = append(noms, c)
	}
	sort.Strings(noms)
	paths := make(map[string]any, len(noms))
	for _, c := range noms {
		paths[c] = chemins[c]
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":   "Vaultaire — API REST",
			"version": storage.Host_Version,
			"description": "Interface REST du registre d'actions de Vaultaire : chaque route appelle l'action " +
				"qu'appelle la commande vlt du même geste, avec les mêmes droits. Authentification : signature " +
				"SSH du compte, voir docs/Utilisation/API_REST.md.",
		},
		"servers":  []map[string]any{{"url": "/"}},
		"security": []map[string]any{{"vaultaireSSH": []string{}}},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"vaultaireSSH": map[string]any{
					"type": "apiKey", "in": "header", "name": "Authorization",
					"description": "« Vaultaire-SSH <signature> » avec X-Vaultaire-User, X-Vaultaire-Timestamp, " +
						"X-Vaultaire-Nonce. La signature (clé SSH du compte) couvre méthode, chemin, requête, " +
						"compte, horodatage, nonce et SHA-256 du corps. `vlt api` la produit.",
				},
			},
			"schemas": map[string]any{
				"Reponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"ok":         map[string]any{"type": "boolean"},
						"action":     map[string]any{"type": "string"},
						"message":    map[string]any{"type": "string"},
						"data":       map[string]any{"nullable": true},
						"request_id": map[string]any{"type": "string"},
						"error": map[string]any{"type": "object", "properties": map[string]any{
							"code": map[string]any{"type": "string", "enum": []string{
								codeNonAuthentifie, codeRefuse, codeRequeteInvalide, codeIntrouvable, codeActionInconnue,
								codeConfirmationRequise, codeActionEchouee, codeTropDeRequetes, codeTropVolumineux, codeMethodeRefusee}},
							"message": map[string]any{"type": "string"},
							"key":     map[string]any{"type": "string"},
							"replay":  map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
						}},
					},
				},
			},
		},
		"paths": paths,
	}
}

func operation(nomAction, resume, tag string, statut int, params []map[string]any) map[string]any {
	op := map[string]any{
		"tags":      []string{tag},
		"summary":   resume,
		"responses": reponses(statut),
	}
	if nomAction != "" {
		op["operationId"] = nomAction
		op["description"] = "Action du registre : `" + nomAction + "` (mêmes droits que la commande vlt)."
	}
	if len(params) > 0 {
		op["parameters"] = params
	}
	return op
}

func parametresDeChemin(chemin string) []map[string]any {
	var out []map[string]any
	for _, m := range motifParametre.FindAllStringSubmatch(chemin, -1) {
		out = append(out, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
	}
	return out
}

func corpsParametres() map[string]any {
	return map[string]any{"content": map[string]any{"application/json": map[string]any{
		"schema": map[string]any{"type": "object", "description": "paramètres de l'action — mêmes noms que les champs du portail",
			"additionalProperties": map[string]any{}},
	}}}
}

func reponses(statut int) map[string]any {
	ref := map[string]any{"content": map[string]any{"application/json": map[string]any{
		"schema": map[string]any{"$ref": "#/components/schemas/Reponse"}}}}
	out := map[string]any{}
	for code, desc := range map[int]string{
		statut: "succès",
		400:    "paramètres invalides (bad_request)",
		401:    "authentification refusée (unauthenticated)",
		403:    "droit refusé (forbidden)",
		404:    "introuvable (not_found, unknown_action)",
		409:    "confirmation requise (confirmation_required)",
		422:    "l'action a échoué (action_failed)",
		429:    "trop de requêtes (too_many_requests)",
	} {
		r := map[string]any{"description": desc}
		for k, v := range ref {
			r[k] = v
		}
		out[strconv.Itoa(code)] = r
	}
	return out
}
