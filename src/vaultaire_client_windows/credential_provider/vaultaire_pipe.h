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

// Les délais d'un échange, en millisecondes. Ils sont tenus PAR LA DLL (TO-DO 156).
//
// LogonUI appelle le fournisseur sur le fil qui dessine l'écran de connexion.
// Une lecture sans échéance sur le tube y retient donc l'écran entier, et pas
// seulement notre tuile. Avant ce point, la seule borne était le veilleur de
// l'agent, c'est-à-dire celle du processus dont on attendait justement la
// réponse : un agent figé retenait LogonUI sans limite.
//
// Deux délais, parce que les deux questions n'ont pas le même prix :
//
//   - l'ÉTAT est demandé à la sélection de la tuile, donc à l'affichage de
//     l'écran. L'agent y répond de mémoire, sans réseau. Une seconde et demie
//     est déjà longue ; au-delà, on affiche « ne répond pas » et l'écran vit.
//   - l'AUTHENTIFICATION attend le core. L'agent borne lui-même son traitement
//     à vingt secondes et rend alors un verdict « délai » : on lui laisse cinq
//     secondes de plus pour que ce soit SON verdict qui arrive, et non notre
//     coupure — les deux n'ont pas la même cause.
const DWORD kDelaiEtatMs = 1500;
const DWORD kDelaiAuthMs = 25000;

// Durée au-delà de laquelle une authentification est signalée « lente » dans
// le journal. L'agent borne l'attente du core à sept secondes : au-delà de
// huit, ce n'est plus un lien lent, c'est l'agent qui a tardé.
const DWORD kAuthLenteMs = 8000;

// Statuts rendus par l'agent.
enum class Statut {
  kSucces,         // mot de passe validé, compte local prêt
  kRefus,          // le core a refusé
  kIndisponible,   // aucun core joignable
  kDelai,          // le core n'a pas répondu
  kAgentAbsent,    // le tube n'existe pas : service arrêté ou non installé
  kErreurLocale,   // échec d'appel système ou réponse illisible
  // Ajouté EN FIN d'énumération : le journal écrit le statut par son numéro
  // (« refus pour … (statut N) »), et insérer au milieu changerait le sens des
  // lignes déjà écrites sur les postes.
  kAgentMuet,      // le tube existe, l'agent n'a pas répondu dans le délai
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
//
// # Une chaîne large s'écrit %ls, JAMAIS %s (TO-DO 140)
//
// Le format est large (L"…"), et MinGW y lit `%s` comme une chaîne ÉTROITE —
// l'inverse de MSVC. Une chaîne large passée à `%s` s'arrête à son premier
// octet nul, c'est-à-dire après UN caractère : le journal disait « fournisseur
// charge : C » et « session ouverte pour a ». `%ls` a le même sens dans les
// deux compilateurs. GCC ne vérifie pas les formats larges : c'est
// build-cp.sh qui refuse un `%s` dans un littéral L"…".
void Journaliser(const wchar_t* format, ...);

}  // namespace vaultaire
