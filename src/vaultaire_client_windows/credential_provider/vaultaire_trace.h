// La TRACE du fournisseur : qui appelle quoi, dans quel ordre, et pour combien
// de temps (TO-DO 156).
//
// # Pourquoi elle existe
//
// Le journal ordinaire dit trois choses : la DLL est inscrite, LogonUI l'a
// chargée, le scénario est accepté. Après quoi il se tait — que tout aille bien
// ou que l'écran de connexion reste vide. Un écran sans aucune tuile, pas même
// celles de Windows, laissait donc exactement les mêmes lignes qu'une ouverture
// de session réussie : rien ne disait dans quelle méthode LogonUI s'était
// arrêté, ni même s'il s'était arrêté chez nous.
//
// La trace écrit une ligne à l'ENTRÉE de chaque méthode COM et une à la SORTIE,
// avec le fil, le résultat et la durée. Une entrée sans sortie nomme la méthode
// où LogonUI est resté — blocage ou plantage. Une suite complète qui se termine
// par des résultats corrects dit que la panne n'est pas dans la DLL.
//
// # Comment on l'allume
//
// Par un FICHIER-TÉMOIN, et non par une valeur de registre :
//
//     C:\ProgramData\Vaultaire\logs\credential_provider.trace
//
// Un poste dont l'écran de connexion est vide ne se règle plus de l'intérieur.
// Un fichier se pose et se retire par le partage administratif (\\poste\c$),
// depuis le mode sans échec ou depuis un disque monté ailleurs ; une valeur de
// registre demande une session ou le registre à distance. Son contenu est
// ignoré : seule sa présence compte.
//
// # Ce qui n'y entre JAMAIS
//
// Aucune valeur saisie. SetStringValue trace le RANG du champ, pas ce qu'on y
// tape — ni le mot de passe, ni le code, ni leur longueur. Les lignes de trace
// vont dans le même fichier que le journal ordinaire, lisible par les
// administrateurs du poste.

#pragma once

#include <windows.h>
#include <string>

namespace vaultaire {

// Le fichier-témoin. À côté du journal, pour qu'on le trouve en le cherchant.
const wchar_t* const kTemoinTrace =
    L"C:\\ProgramData\\Vaultaire\\logs\\credential_provider.trace";

// Au-delà de cette taille de journal, la trace se coupe d'elle-même.
//
// Rien ne fait tourner ce fichier, et un témoin oublié sur un poste écrirait
// une centaine de lignes à chaque affichage de l'écran de connexion, sans fin.
// Huit mégaoctets : plusieurs milliers d'affichages, bien plus qu'un diagnostic.
const ULONGLONG kTailleMaxAvecTrace = 8ULL * 1024 * 1024;

// Une méthode qui dure plus que cela est signalée MÊME SANS trace.
//
// LogonUI appelle le fournisseur sur ses propres fils : une seconde passée
// chez nous est une seconde où il n'avance pas. C'est le seul signal que le
// journal ordinaire donne d'une lenteur, et il ne coûte qu'une lecture
// d'horloge par appel.
const DWORD kSeuilLenteurMs = 1000;

// RelireTemoinTrace regarde si le témoin est là. Appelée à chaque activation de
// la DLL et à chaque changement de scénario : poser ou retirer le fichier prend
// effet au prochain affichage de l'écran, sans redémarrage.
void RelireTemoinTrace();

// TraceActive rend le dernier état lu. Ne touche pas au disque.
bool TraceActive();

// Tracer écrit une ligne « trace fil=N … » si la trace est allumée.
// Format large : une chaîne large s'écrit %ls, jamais %s (voir Journaliser).
void Tracer(const wchar_t* format, ...);

// NomDeLInterface rend le nom d'une interface connue, ou son GUID en texte.
//
// Les interfaces que LogonUI DEMANDE disent ce qu'il attend du fournisseur, y
// compris celles qu'on lui refuse : c'est la seule façon de le voir.
std::wstring NomDeLInterface(REFIID riid);

// Passage : l'entrée et la sortie d'une méthode.
//
//     Passage p(L"GetFieldState", L"champ=%lu", champ);
//     ...
//     return p.Rendre(S_OK);
//
// La sortie est écrite par le destructeur : aucun chemin de retour ne peut
// l'oublier. Rendre() n'est là que pour que la ligne porte le résultat.
class Passage {
 public:
  explicit Passage(const wchar_t* methode);
  Passage(const wchar_t* methode, const wchar_t* format, ...);
  ~Passage();

  HRESULT Rendre(HRESULT hr) {
    resultat_ = hr;
    rendu_ = true;
    return hr;
  }

  // Tolerer relève le seuil de lenteur de CE passage.
  //
  // Pour la seule méthode qui a le droit d'attendre : GetSerialization, qui
  // interroge le core à travers l'agent. Sans cela, chaque ouverture de session
  // sur un lien lent écrirait « lent » dans le journal, et la ligne ne
  // voudrait plus rien dire le jour où elle signale une vraie panne.
  void Tolerer(DWORD seuil_ms) { seuil_ms_ = seuil_ms; }

 private:
  Passage(const Passage&) = delete;
  Passage& operator=(const Passage&) = delete;

  const wchar_t* methode_;
  bool actif_;
  bool rendu_;
  HRESULT resultat_;
  DWORD debut_;
  DWORD seuil_ms_ = kSeuilLenteurMs;
};

}  // namespace vaultaire
