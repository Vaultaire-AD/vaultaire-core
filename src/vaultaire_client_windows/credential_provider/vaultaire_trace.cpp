#include "vaultaire_trace.h"
#include "vaultaire_pipe.h"

#include <credentialprovider.h>
#include <stdarg.h>
#include <stdio.h>

namespace vaultaire {
namespace {

// 0 : jamais lu ; 1 : éteinte ; 2 : allumée. Un LONG lu et écrit d'un seul
// tenant : la DLL est appelée depuis plusieurs fils de LogonUI, et une course
// ici ne coûte au pire qu'une ligne de trace en trop ou en moins.
volatile LONG g_etat = 0;

const wchar_t* const kCheminDuJournal =
    L"C:\\ProgramData\\Vaultaire\\logs\\credential_provider.log";

struct InterfaceConnue {
  const IID* iid;
  const wchar_t* nom;
};

const InterfaceConnue kInterfaces[] = {
    {&IID_IUnknown, L"IUnknown"},
    {&IID_IClassFactory, L"IClassFactory"},
    {&IID_ICredentialProvider, L"ICredentialProvider"},
    {&IID_ICredentialProviderSetUserArray, L"ICredentialProviderSetUserArray"},
    {&IID_ICredentialProviderFilter, L"ICredentialProviderFilter"},
    {&IID_ICredentialProviderCredential, L"ICredentialProviderCredential"},
    {&IID_ICredentialProviderCredential2, L"ICredentialProviderCredential2"},
    {&IID_ICredentialProviderCredentialWithFieldOptions,
     L"ICredentialProviderCredentialWithFieldOptions"},
    {&IID_IConnectableCredentialProviderCredential, L"IConnectableCredentialProviderCredential"},
};

// Formater compose une ligne dans un tampon borné. Tronquée plutôt que
// débordée : une ligne de trace coupée reste lisible, un tampon dépassé dans
// LogonUI fait disparaître l'écran de connexion.
void Formater(wchar_t* tampon, size_t taille, const wchar_t* format, va_list args) {
  _vsnwprintf(tampon, taille - 1, format, args);
  tampon[taille - 1] = L'\0';
}

}  // namespace

void RelireTemoinTrace() {
  const bool present = GetFileAttributesW(kTemoinTrace) != INVALID_FILE_ATTRIBUTES;
  if (!present) {
    InterlockedExchange(&g_etat, 1);
    return;
  }

  WIN32_FILE_ATTRIBUTE_DATA infos;
  if (GetFileAttributesExW(kCheminDuJournal, GetFileExInfoStandard, &infos)) {
    const ULONGLONG taille = ((ULONGLONG)infos.nFileSizeHigh << 32) | infos.nFileSizeLow;
    if (taille > kTailleMaxAvecTrace) {
      // Dit une seule fois par passage d'allumée à coupée, pas à chaque appel.
      if (InterlockedExchange(&g_etat, 1) != 1) {
        Journaliser(L"trace coupee : le journal depasse %lu Mo (retirer %ls, ou vider le journal)",
                    (unsigned long)(kTailleMaxAvecTrace / (1024 * 1024)), kTemoinTrace);
      }
      return;
    }
  }

  if (InterlockedExchange(&g_etat, 2) != 2) {
    Journaliser(L"trace allumee par %ls (processus %lu)", kTemoinTrace,
                (unsigned long)GetCurrentProcessId());
  }
}

bool TraceActive() {
  if (g_etat == 0) RelireTemoinTrace();
  return g_etat == 2;
}

void Tracer(const wchar_t* format, ...) {
  if (!TraceActive()) return;
  wchar_t ligne[320];
  va_list args;
  va_start(args, format);
  Formater(ligne, 320, format, args);
  va_end(args);
  Journaliser(L"trace fil=%lu %ls", (unsigned long)GetCurrentThreadId(), ligne);
}

std::wstring NomDeLInterface(REFIID riid) {
  for (const InterfaceConnue& connue : kInterfaces) {
    if (riid == *connue.iid) return connue.nom;
  }
  wchar_t texte[64] = {0};
  if (StringFromGUID2(riid, texte, 64) <= 0) return L"(interface illisible)";
  return texte;
}

Passage::Passage(const wchar_t* methode)
    : methode_(methode), actif_(TraceActive()), rendu_(false), resultat_(S_OK),
      debut_(GetTickCount()) {
  if (actif_) Tracer(L"> %ls", methode_);
}

Passage::Passage(const wchar_t* methode, const wchar_t* format, ...)
    : methode_(methode), actif_(TraceActive()), rendu_(false), resultat_(S_OK),
      debut_(GetTickCount()) {
  if (!actif_) return;
  wchar_t detail[200];
  va_list args;
  va_start(args, format);
  Formater(detail, 200, format, args);
  va_end(args);
  Tracer(L"> %ls %ls", methode_, detail);
}

Passage::~Passage() {
  // Soustraction non signée : juste même quand le compteur repasse par zéro.
  const DWORD duree = GetTickCount() - debut_;
  if (actif_) {
    if (rendu_) {
      Tracer(L"< %ls = 0x%08lx (%lu ms)", methode_, (unsigned long)resultat_,
             (unsigned long)duree);
    } else {
      Tracer(L"< %ls (%lu ms)", methode_, (unsigned long)duree);
    }
    return;
  }
  if (duree >= seuil_ms_) {
    Journaliser(L"lent : %ls a retenu LogonUI %lu ms", methode_, (unsigned long)duree);
  }
}

}  // namespace vaultaire
