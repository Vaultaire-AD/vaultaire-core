#include "vaultaire_pipe.h"

#include <stdio.h>
#include <stdarg.h>

#include <string>
#include <vector>

namespace vaultaire {
namespace {

// --- journal -----------------------------------------------------------------

const wchar_t* const kCheminJournal =
    L"C:\\ProgramData\\Vaultaire\\logs\\credential_provider.log";

// --- conversions -------------------------------------------------------------

std::string VersUtf8(const std::wstring& s) {
  if (s.empty()) return std::string();
  int taille = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
  std::string sortie((size_t)taille, '\0');
  WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &sortie[0], taille, nullptr, nullptr);
  return sortie;
}

std::wstring DepuisUtf8(const std::string& s) {
  if (s.empty()) return std::wstring();
  int taille = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
  std::wstring sortie((size_t)taille, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &sortie[0], taille);
  return sortie;
}

// EchapperJSON protège les caractères qui casseraient le message.
//
// Un mot de passe contient volontiers des guillemets et des contre-obliques.
// Sans échappement, le message envoyé ne serait plus du JSON — l'agent le
// refuserait — ou, pire, porterait des champs déplacés.
std::string EchapperJSON(const std::string& s) {
  std::string sortie;
  sortie.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"':  sortie += "\\\""; break;
      case '\\': sortie += "\\\\"; break;
      case '\n': sortie += "\\n";  break;
      case '\r': sortie += "\\r";  break;
      case '\t': sortie += "\\t";  break;
      default:
        if (c < 0x20) {
          char tampon[7];
          sprintf(tampon, "\\u%04x", c);
          sortie += tampon;
        } else {
          sortie += (char)c;
        }
    }
  }
  return sortie;
}

// LireChaine extrait "cle":"valeur" d'une réponse.
//
// Lecture par recherche de clé, et non analyse complète : la réponse de l'agent
// est un objet plat de cinq champs, produit par encoding/json — pas un document
// arbitraire. Un analyseur généraliste serait plus de code à charger dans
// LogonUI pour exactement le même résultat.
bool LireChaine(const std::string& json, const char* cle, std::string* valeur) {
  std::string motif = std::string("\"") + cle + "\":\"";
  size_t i = json.find(motif);
  if (i == std::string::npos) return false;
  i += motif.size();
  std::string sortie;
  while (i < json.size() && json[i] != '"') {
    if (json[i] == '\\' && i + 1 < json.size()) {
      ++i;
      switch (json[i]) {
        case 'n': sortie += '\n'; break;
        case 'r': sortie += '\r'; break;
        case 't': sortie += '\t'; break;
        default:  sortie += json[i];
      }
    } else {
      sortie += json[i];
    }
    ++i;
  }
  *valeur = sortie;
  return true;
}

bool LireBooleen(const std::string& json, const char* cle) {
  std::string motif = std::string("\"") + cle + "\":true";
  return json.find(motif) != std::string::npos;
}

Statut StatutDepuis(const std::string& texte) {
  if (texte == "success")     return Statut::kSucces;
  if (texte == "failed")      return Statut::kRefus;
  if (texte == "unavailable") return Statut::kIndisponible;
  if (texte == "timeout")     return Statut::kDelai;
  return Statut::kErreurLocale;
}

// Borner attend la fin d'une lecture ou d'une écriture lancée sur le tube, au
// plus jusqu'à l'échéance de l'échange.
//
// Rend faux si l'opération a échoué OU si l'échéance est passée ; `muet` dit
// lequel des deux. Sur échéance, l'opération est ANNULÉE et sa fin attendue
// avant de rendre la main : OVERLAPPED vit sur la pile de l'appelant, et le
// noyau y écrirait après son retour.
bool Borner(HANDLE tube, OVERLAPPED* op, BOOL lancee, DWORD debut, DWORD delai_ms,
            DWORD* octets, bool* muet) {
  *octets = 0;
  if (!lancee) {
    if (GetLastError() != ERROR_IO_PENDING) return false;
    // Soustraction non signée : juste même quand le compteur repasse par zéro.
    const DWORD ecoule = GetTickCount() - debut;
    const DWORD reste = (ecoule < delai_ms) ? delai_ms - ecoule : 0;
    if (WaitForSingleObject(op->hEvent, reste) != WAIT_OBJECT_0) {
      *muet = true;
      CancelIoEx(tube, op);
      GetOverlappedResult(tube, op, octets, TRUE);
      *octets = 0;
      return false;
    }
  }
  return GetOverlappedResult(tube, op, octets, FALSE) != 0;
}

// Echanger ouvre le tube, envoie, lit, referme — en `delai_ms` au plus.
//
// # Asynchrone, pour pouvoir s'arrêter (TO-DO 156)
//
// Le tube était ouvert en mode synchrone : WriteFile, FlushFileBuffers et
// ReadFile y attendent l'agent sans limite. Un agent vivant mais figé — tube
// créé, personne pour lire — retenait donc LogonUI indéfiniment, et l'écran de
// connexion restait vide. Le mode asynchrone est la seule façon de poser une
// échéance que le client tient lui-même.
//
// FlushFileBuffers a disparu : sur un tube, il attend que le serveur ait LU —
// c'est-à-dire exactement l'attente sans borne qu'on retire. Il ne servait à
// rien : la requête est dans le tampon du tube dès que WriteFile rend la main,
// et c'est la lecture de la réponse qui attend l'agent.
Reponse Echanger(const std::string& requete, DWORD delai_ms) {
  Reponse reponse;

  HANDLE tube = INVALID_HANDLE_VALUE;
  const DWORD debut = GetTickCount();
  for (;;) {
    tube = CreateFileW(kNomTube, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                       OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (tube != INVALID_HANDLE_VALUE) break;

    const DWORD erreur = GetLastError();
    if (erreur != ERROR_PIPE_BUSY) {
      // Le tube n'existe pas : le service est arrêté, ou l'agent n'est pas
      // installé. Ce cas est NOMMÉ parce que c'est le plus fréquent en
      // déploiement, et qu'il n'a rien à voir avec un mot de passe.
      Journaliser(L"tube injoignable (erreur %lu)", erreur);
      reponse.statut = Statut::kAgentAbsent;
      return reponse;
    }
    // Toutes les instances sont occupées : d'autres sessions s'authentifient.
    const DWORD ecoule = GetTickCount() - debut;
    if (ecoule >= delai_ms ||
        !WaitNamedPipeW(kNomTube, (delai_ms - ecoule < 1000) ? delai_ms - ecoule : 1000)) {
      Journaliser(L"tube occupé, délai dépassé");
      reponse.statut = Statut::kAgentAbsent;
      return reponse;
    }
  }

  // Un événement à remise MANUELLE, comme l'exige GetOverlappedResult ; il sert
  // aux deux sens, l'un après l'autre.
  HANDLE fini = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (fini == nullptr) {
    Journaliser(L"événement d'attente impossible (erreur %lu)", GetLastError());
    CloseHandle(tube);
    return reponse;  // kErreurLocale
  }

  bool muet = false;
  DWORD ecrits = 0;
  OVERLAPPED op;
  ZeroMemory(&op, sizeof(op));
  op.hEvent = fini;
  BOOL lancee = WriteFile(tube, requete.data(), (DWORD)requete.size(), nullptr, &op);
  if (!Borner(tube, &op, lancee, debut, delai_ms, &ecrits, &muet) || ecrits != requete.size()) {
    if (muet) {
      Journaliser(L"agent muet : requete non lue en %lu ms", (unsigned long)delai_ms);
      reponse.statut = Statut::kAgentMuet;
    } else {
      Journaliser(L"écriture sur le tube échouée (erreur %lu)", GetLastError());
    }
    CloseHandle(fini);
    CloseHandle(tube);
    return reponse;
  }

  std::string brut;
  char tampon[512];
  for (;;) {
    DWORD lus = 0;
    ZeroMemory(&op, sizeof(op));
    op.hEvent = fini;
    lancee = ReadFile(tube, tampon, sizeof(tampon), nullptr, &op);
    if (!Borner(tube, &op, lancee, debut, delai_ms, &lus, &muet) || lus == 0) break;
    brut.append(tampon, lus);
    if (brut.size() > 8192) break;              // borne : voir ipc.TailleMaxRequete
    if (brut.find('\n') != std::string::npos) break;  // une réponse = une ligne
  }
  CloseHandle(fini);
  CloseHandle(tube);

  if (muet) {
    // Nommé à part de « réponse vide » : ici l'agent TIENT le tube et ne dit
    // rien. C'est un agent figé, pas un agent qui a raccroché.
    Journaliser(L"agent muet : aucune reponse en %lu ms", (unsigned long)delai_ms);
    reponse.statut = Statut::kAgentMuet;
    return reponse;
  }

  if (brut.empty()) {
    Journaliser(L"réponse vide de l'agent");
    return reponse;
  }

  std::string statut;
  if (!LireChaine(brut, "status", &statut)) {
    Journaliser(L"réponse sans statut");
    return reponse;
  }
  reponse.statut = StatutDepuis(statut);
  reponse.administrateur = LireBooleen(brut, "is_admin");
  reponse.raccorde = LireBooleen(brut, "connected");

  std::string valeur;
  if (LireChaine(brut, "local_account", &valeur)) reponse.compte_local = DepuisUtf8(valeur);
  if (LireChaine(brut, "message", &valeur))       reponse.message = DepuisUtf8(valeur);
  return reponse;
}

}  // namespace

void Journaliser(const wchar_t* format, ...) {
  FILE* f = nullptr;
  if (_wfopen_s(&f, kCheminJournal, L"a, ccs=UTF-8") != 0 || f == nullptr) return;

  SYSTEMTIME t;
  GetLocalTime(&t);
  fwprintf(f, L"%04d-%02d-%02d %02d:%02d:%02d [CP] ",
           t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);

  va_list args;
  va_start(args, format);
  vfwprintf(f, format, args);
  va_end(args);

  fwprintf(f, L"\n");
  fclose(f);
}

Reponse Authentifier(const std::wstring& utilisateur, const std::wstring& mot_de_passe,
                     const std::wstring& code) {
  // Le champ « otp » est TOUJOURS écrit, même vide : sa PRÉSENCE dit à l'agent,
  // puis au core, qu'ils parlent à une tuile récente. L'omettre quand il est
  // vide la ferait passer pour une tuile ancienne, et le core laisserait passer
  // sans second facteur (TO-DO 95).
  std::string requete = "{\"type\":\"auth\",\"user\":\"" +
                        EchapperJSON(VersUtf8(utilisateur)) + "\",\"password\":\"" +
                        EchapperJSON(VersUtf8(mot_de_passe)) + "\",\"otp\":\"" +
                        EchapperJSON(VersUtf8(code)) + "\"}\n";

  Reponse reponse = Echanger(requete, kDelaiAuthMs);

  // Le mot de passe ne doit pas rester dans la mémoire de LogonUI : SecureZeroMemory
  // plutôt que memset, que le compilateur a le droit de supprimer sur un tampon
  // qui n'est plus lu ensuite.
  SecureZeroMemory(&requete[0], requete.size());
  return reponse;
}

Reponse Etat() {
  return Echanger("{\"type\":\"etat\"}\n", kDelaiEtatMs);
}

}  // namespace vaultaire
