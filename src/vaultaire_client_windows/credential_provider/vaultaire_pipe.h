// Le dialogue avec l'agent : un tube nommé, un message, une réponse.
//
// Ce fichier est le pendant C++ de src/vaultaire_client_windows/ipc. Les deux
// vivent dans des langages différents et rien ne peut les tenir liés à la
// compilation : le nom du tube, les noms de champs et les statuts sont donc
// écrits des deux côtés, et toute divergence donne un échec NET — « le service
// Vaultaire ne répond pas » — plutôt qu'un comportement douteux.
//
// Pas de bibliothèque JSON. La DLL est chargée dans LogonUI.exe, le processus
// qui dessine l'écran de connexion : ce qui plante là fait disparaître l'écran
// de connexion de la machine. Les messages échangés tiennent en quatre champs
// plats ; les composer à la main et lire la réponse par recherche de clé coûte
// cent lignes et n'ajoute aucune dépendance.

#pragma once

#include <windows.h>
#include <string>

namespace vaultaire {

// Le nom du tube. Écrit aussi dans ipc/protocole.go (constante NomTube).
const wchar_t* const kNomTube = L"\\\\.\\pipe\\vaultaire_agent";

// Délai total d'un échange, en millisecondes.
//
// Vingt secondes : l'agent borne lui-même l'attente du core à sept secondes,
// et il faut laisser passer un tunnel en cours de rétablissement. Au-delà,
// l'utilisateur devant l'écran conclut que la machine est morte.
const DWORD kDelaiEchangeMs = 20000;

// Statuts rendus par l'agent.
enum class Statut {
  kSucces,         // mot de passe validé, compte local prêt
  kRefus,          // le core a refusé
  kIndisponible,   // aucun core joignable
  kDelai,          // le core n'a pas répondu
  kAgentAbsent,    // le tube n'existe pas : service arrêté ou non installé
  kErreurLocale,   // échec d'appel système ou réponse illisible
};

// Reponse est ce que l'agent a dit.
struct Reponse {
  Statut statut = Statut::kErreurLocale;
  bool administrateur = false;
  bool raccorde = false;
  // Le compte Windows LOCAL à qui la session doit être ouverte. Il diffère de
  // l'identifiant du domaine : Windows refuse « @ » dans un nom local.
  std::wstring compte_local;
  std::wstring message;
};

// Authentifier soumet un identifiant, un mot de passe et un code de second
// facteur à l'agent (TO-DO 95).
//
// Le code vaut « 0000 » pour un compte qui n'a pas de second facteur : c'est ce
// que dit le libellé du champ, et le core ne l'accepte QUE pour un tel compte.
//
// Les deux secrets sont effacés du tampon d'envoi avant retour : ils ne doivent
// pas traîner dans la mémoire de LogonUI plus longtemps que nécessaire.
Reponse Authentifier(const std::wstring& utilisateur, const std::wstring& mot_de_passe,
                     const std::wstring& code);

// Etat demande si l'agent est raccordé à un core. Sert à prévenir AVANT la
// saisie : « service indisponible » au premier écran vaut mieux qu'un refus
// après le mot de passe.
Reponse Etat();

// Journaliser écrit une ligne dans le journal de la DLL.
//
// Fichier séparé de celui de l'agent : les deux processus n'ont ni le même
// cycle de vie ni les mêmes droits, et mélanger leurs lignes rendrait
// illisible la seule trace qu'on ait de l'écran de connexion.
void Journaliser(const wchar_t* format, ...);

}  // namespace vaultaire
