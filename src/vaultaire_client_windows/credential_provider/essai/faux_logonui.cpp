// faux_logonui.exe — joue contre la DLL la suite d'appels de LogonUI (TO-DO 149).
//
// # Ce que c'est, et ce que ce n'est pas
//
// LogonUI ne se lance pas hors d'un vrai écran de connexion. Ce programme en
// rejoue le PROTOCOLE : il active le fournisseur par COM, comme LogonUI, puis
// appelle ses méthodes dans l'ordre où LogonUI les appelle, et vérifie chaque
// réponse. Il tourne sous wine dans la fabrication (essai-wine.sh), et tel quel
// sur un vrai Windows.
//
// Ce n'est PAS LogonUI : rien ici n'affiche la tuile, et un défaut qui ne se
// voit qu'à l'écran — une tuile qui n'apparaît pas alors que toutes les
// méthodes répondent juste (TO-DO 157) — passe à travers. La tuile reste une
// recette manuelle (A_TESTER.md).
//
// # Les trois agents
//
// La tuile parle à l'agent par un tube nommé. Le programme tient lui-même le
// rôle de l'agent, de trois façons :
//
//   absent     aucun tube : le service est arrêté ;
//   muet       le tube existe, personne n'y répond — le cas qui figeait
//              LogonUI sans limite avant le TO-DO 156 ;
//   répondant  un agent minimal : « raccordé » à la question d'état, « refusé »
//              à toute authentification.
//
// La soumission face à un agent MUET n'est pas jouée : elle attend kDelaiAuthMs
// (25 s) par construction, ce qui doublerait la durée de la fabrication pour
// un chemin déjà borné par le même code que SetSelected.
//
// # Sortie
//
// Une ligne par contrôle (« ok » ou « ECHEC »), en ASCII : la console de wine
// et les journaux de CI ne s'entendent pas toujours sur l'encodage. Le code de
// sortie est le nombre d'échecs — 0 quand tout est juste.
//
// # Les variantes d'essai (TO-DO 157)
//
//   faux_logonui.exe --variantes
//
// La même suite, quand essai-wine.sh a posé les trois valeurs de
// HKLM\SOFTWARE\Vaultaire\CredentialProvider (TuileParDefaut, ModeV1,
// SansImage) : ce qui doit changer change, et rien d'autre.
//
// Format large : une chaîne large s'écrit %ls, jamais %s (voir build-cp.sh).

#include "vaultaire_guid.h"

#include <windows.h>
#include <credentialprovider.h>
// Les rôles de champ du SDK, pour les comparer à ceux que la DLL recopie.
#include <shlguid.h>
#include <stdarg.h>
#include <stdio.h>

#include <string>
#include <vector>

namespace {

// --- ce que la DLL doit rendre ---------------------------------------------
//
// Recopié de vaultaire_credential.h et vaultaire_pipe.h, et non inclus : un
// essai qui lit ses attentes dans le code qu'il éprouve ne trouve jamais
// l'erreur qu'ils partagent. Si l'un change, l'essai rougit, et c'est voulu —
// l'ordre des champs EST l'interface avec Winlogon.
const DWORD kNombreDeChamps = 8;
const DWORD kChampTitre = 0, kChampUtilisateur = 1, kChampMotDePasse = 2, kChampCode = 3,
            kChampValider = 4, kChampMessage = 5, kChampImage = 6, kChampLibelle = 7;
const CREDENTIAL_PROVIDER_FIELD_TYPE kTypes[kNombreDeChamps] = {
    CPFT_LARGE_TEXT, CPFT_EDIT_TEXT, CPFT_PASSWORD_TEXT,
    CPFT_PASSWORD_TEXT, CPFT_SUBMIT_BUTTON, CPFT_SMALL_TEXT,
    CPFT_TILE_IMAGE, CPFT_SMALL_TEXT,
};

// Le rôle attendu de chaque champ (TO-DO 157) : celui du SDK, lu dans shlguid.h.
const GUID kAucunRole = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
const GUID* RoleAttendu(DWORD champ) {
  if (champ == kChampImage) return &CPFG_CREDENTIAL_PROVIDER_LOGO;
  if (champ == kChampLibelle) return &CPFG_CREDENTIAL_PROVIDER_LABEL;
  return &kAucunRole;
}

// --variantes : les trois valeurs d'essai sont posées.
bool g_variantes = false;

const wchar_t kTube[] = L"\\\\.\\pipe\\vaultaire_agent";

// Bornes de durée. SetSelected attend l'agent kDelaiEtatMs (1,5 s) au plus ;
// la marge couvre la lenteur de wine sur une machine de CI chargée, pas une
// attente de plus : un SetSelected qui retient LogonUI plus de 3 s est un
// défaut, quel que soit l'hôte.
const DWORD kBorneSetSelectedMs = 3000;
const DWORD kBorneImmediateMs = 2000;

// Les valeurs tapées. Le script cherche ensuite le mot de passe et le code
// dans le journal : ils ne doivent JAMAIS y être, trace allumée comprise.
const wchar_t kUtilisateur[] = L"essai149@vaultaire.test";
const wchar_t kMotDePasse[] = L"MotDePasse-Essai-149";
const wchar_t kCode[] = L"314159";

int g_echecs = 0;
int g_controles = 0;

// Le dernier endroit atteint, pour le chien de garde.
char g_section[96] = "demarrage";
char g_dernier[256] = "(aucun controle)";

// Au-delà, l'essai est déclaré BLOQUÉ. Une suite complète dure quelques
// secondes ; un SetSelected sans échéance — le défaut du TO-DO 156 — ne
// rendrait jamais la main, et la fabrication attendrait avec lui.
const DWORD kChienDeGardeMs = 90000;

void Verifier(bool condition, const char* format, ...) {
  ++g_controles;
  char ligne[512];
  va_list args;
  va_start(args, format);
  vsnprintf(ligne, sizeof(ligne), format, args);
  va_end(args);
  snprintf(g_dernier, sizeof(g_dernier), "%s", ligne);
  if (condition) {
    printf("  ok     %s\n", ligne);
  } else {
    ++g_echecs;
    printf("  ECHEC  %s\n", ligne);
  }
  fflush(stdout);
}

void Section(const char* titre) {
  snprintf(g_section, sizeof(g_section), "%s", titre);
  printf("\n== %s\n", titre);
  fflush(stdout);
}

// Le chien de garde : une méthode qui ne rend pas la main est le défaut le
// plus grave qu'un fournisseur puisse avoir — l'écran de connexion reste figé.
// Il est nommé, et l'essai s'arrête, au lieu d'attendre indéfiniment.
DWORD WINAPI ChienDeGarde(LPVOID) {
  Sleep(kChienDeGardeMs);
  printf("  ECHEC  BLOQUE : l'essai depasse %lu s\n", (unsigned long)(kChienDeGardeMs / 1000));
  printf("         section : %s\n", g_section);
  printf("         apres   : %s\n", g_dernier);
  printf("         -> la methode appelee ensuite n'a pas rendu la main (voir TO-DO 156)\n");
  fflush(stdout);
  TerminateProcess(GetCurrentProcess(), 100);
  return 0;
}

// Ascii rend une chaîne large lisible sur la sortie : les caractères hors
// ASCII deviennent « ? ». Pour l'affichage seulement — les comparaisons se
// font sur les chaînes larges.
std::string Ascii(const wchar_t* s) {
  std::string sortie;
  if (s == nullptr) return "(nul)";
  for (; *s; ++s) sortie += (*s < 0x80) ? (char)*s : '?';
  return sortie;
}

bool Egal(const wchar_t* a, const wchar_t* b) {
  return a != nullptr && b != nullptr && wcscmp(a, b) == 0;
}

// --- les événements de la tuile ----------------------------------------------
//
// LogonUI passe à la tuile un objet par lequel elle lui pousse ses changements
// (Advise). Celui-ci les retient, pour vérifier ce que la tuile a voulu
// afficher.
class CEvenements : public ICredentialProviderCredentialEvents {
 public:
  IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
    if (ppv == nullptr) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredentialEvents) {
      *ppv = static_cast<ICredentialProviderCredentialEvents*>(this);
      AddRef();
      return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
  }
  // Objet sur la pile : le compte n'est tenu que pour vérifier qu'il revient
  // à zéro — une tuile qui garde l'objet après UnAdvise le fuit.
  IFACEMETHODIMP_(ULONG) AddRef() override { return ++references; }
  IFACEMETHODIMP_(ULONG) Release() override { return --references; }

  IFACEMETHODIMP SetFieldState(ICredentialProviderCredential*, DWORD,
                               CREDENTIAL_PROVIDER_FIELD_STATE) override { return S_OK; }
  IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential*, DWORD,
                                          CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) override {
    return S_OK;
  }
  IFACEMETHODIMP SetFieldString(ICredentialProviderCredential*, DWORD champ,
                                LPCWSTR valeur) override {
    if (champ < kNombreDeChamps) {
      chaines[champ] = (valeur != nullptr) ? valeur : L"";
      poussees[champ]++;
    }
    return S_OK;
  }
  IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential*, DWORD, BOOL, LPCWSTR) override {
    return S_OK;
  }
  IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential*, DWORD, HBITMAP) override {
    return S_OK;
  }
  IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential*, DWORD, DWORD) override {
    return S_OK;
  }
  IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential*, DWORD, DWORD) override {
    return S_OK;
  }
  IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential*, DWORD, LPCWSTR) override {
    return S_OK;
  }
  IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential*, DWORD, DWORD) override {
    return S_OK;
  }
  IFACEMETHODIMP OnCreatingWindow(HWND* fenetre) override {
    if (fenetre != nullptr) *fenetre = nullptr;
    return S_OK;
  }

  void Oublier() {
    for (DWORD i = 0; i < kNombreDeChamps; ++i) {
      chaines[i].clear();
      poussees[i] = 0;
    }
  }

  LONG references = 0;
  std::wstring chaines[kNombreDeChamps];
  int poussees[kNombreDeChamps] = {0};
};

// --- l'agent simulé -----------------------------------------------------------

enum class Agent { kAbsent, kMuet, kRepondant };

const char* NomAgent(Agent a) {
  switch (a) {
    case Agent::kAbsent: return "absent";
    case Agent::kMuet: return "muet";
    default: return "repondant";
  }
}

struct Serveur {
  Agent mode = Agent::kAbsent;
  HANDLE pret = nullptr;
  HANDLE fil = nullptr;
  volatile LONG arreter = 0;
  std::vector<std::string> requetes;  // ce que la tuile a envoyé (mode répondant)
};

HANDLE CreerInstance() {
  return CreateNamedPipeW(kTube, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                          PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nullptr);
}

// Le fil de l'agent. L'instance SUIVANTE du tube est créée avant de répondre :
// sans cela, la tuile qui enchaîne deux appels trouverait un instant sans
// tube, et l'essai verrait « agent absent » là où l'agent est en marche.
DWORD WINAPI FilDeLAgent(LPVOID parametre) {
  Serveur* s = static_cast<Serveur*>(parametre);
  HANDLE tube = CreerInstance();
  SetEvent(s->pret);
  if (tube == INVALID_HANDLE_VALUE) return 1;

  for (;;) {
    BOOL relie = ConnectNamedPipe(tube, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED;
    if (s->arreter) {
      CloseHandle(tube);
      return 0;
    }
    if (!relie) {
      CloseHandle(tube);
      tube = CreerInstance();
      continue;
    }

    if (s->mode == Agent::kMuet) {
      // Tenir le tube sans jamais le lire : un agent vivant mais figé. La
      // connexion reste ouverte jusqu'à ce que la tuile raccroche d'elle-même.
      HANDLE suivant = CreerInstance();
      while (!s->arreter) {
        DWORD disponibles = 0;
        if (!PeekNamedPipe(tube, nullptr, 0, nullptr, &disponibles, nullptr)) break;
        Sleep(20);
      }
      DisconnectNamedPipe(tube);
      CloseHandle(tube);
      tube = suivant;
      continue;
    }

    HANDLE suivant = CreerInstance();
    std::string requete;
    char tampon[512];
    DWORD lus = 0;
    while (requete.find('\n') == std::string::npos && requete.size() < 8192 &&
           ReadFile(tube, tampon, sizeof(tampon), &lus, nullptr) && lus > 0) {
      requete.append(tampon, lus);
    }
    s->requetes.push_back(requete);

    const char* reponse = (requete.find("\"type\":\"auth\"") != std::string::npos)
                              ? "{\"status\":\"failed\",\"message\":\"refus de l'essai\"}\n"
                              : "{\"status\":\"success\",\"connected\":true}\n";
    DWORD ecrits = 0;
    WriteFile(tube, reponse, (DWORD)strlen(reponse), &ecrits, nullptr);
    FlushFileBuffers(tube);
    DisconnectNamedPipe(tube);
    CloseHandle(tube);
    tube = suivant;
  }
}

bool Demarrer(Serveur* s, Agent mode) {
  s->mode = mode;
  s->requetes.clear();
  s->arreter = 0;
  if (mode == Agent::kAbsent) return true;
  s->pret = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  s->fil = CreateThread(nullptr, 0, FilDeLAgent, s, 0, nullptr);
  return s->fil != nullptr && WaitForSingleObject(s->pret, 5000) == WAIT_OBJECT_0;
}

void Arreter(Serveur* s) {
  if (s->fil == nullptr) return;
  InterlockedExchange(&s->arreter, 1);
  // Le fil attend dans ConnectNamedPipe : une connexion le réveille.
  for (int essai = 0; essai < 50; ++essai) {
    HANDLE h = CreateFileW(kTube, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
      CloseHandle(h);
      if (WaitForSingleObject(s->fil, 200) == WAIT_OBJECT_0) break;
    } else if (WaitForSingleObject(s->fil, 50) == WAIT_OBJECT_0) {
      break;
    }
  }
  WaitForSingleObject(s->fil, 2000);
  CloseHandle(s->fil);
  CloseHandle(s->pret);
  s->fil = nullptr;
  s->pret = nullptr;
}

// --- les phases ------------------------------------------------------------

typedef HRESULT(WINAPI* FnGetClassObject)(REFCLSID, REFIID, void**);
typedef HRESULT(WINAPI* FnCanUnloadNow)();

// Une liste de comptes vide, comme LogonUI en passe une à SetUserArray. Seul
// son compte de références compte : le fournisseur doit la garder, puis la
// rendre.
class CComptes : public ICredentialProviderUserArray {
 public:
  LONG references = 1;
  IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
    if (ppv == nullptr) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderUserArray) {
      *ppv = static_cast<ICredentialProviderUserArray*>(this);
      AddRef();
      return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
  }
  IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&references); }
  IFACEMETHODIMP_(ULONG) Release() override { return InterlockedDecrement(&references); }
  IFACEMETHODIMP SetProviderFilter(REFGUID) override { return S_OK; }
  IFACEMETHODIMP GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* options) override {
    if (options) *options = CPAO_EMPTY_LOCAL;
    return S_OK;
  }
  IFACEMETHODIMP GetCount(DWORD* nombre) override {
    if (nombre) *nombre = 0;
    return S_OK;
  }
  IFACEMETHODIMP GetAt(DWORD, ICredentialProviderUser** compte) override {
    if (compte) *compte = nullptr;
    return E_INVALIDARG;
  }
};
CComptes g_comptes;

// Le fournisseur, tel que LogonUI le trouve : par son CLSID, à travers le
// registre. C'est ce qui prouve que l'inscription mène à la DLL.
ICredentialProvider* Activer() {
  ICredentialProvider* fournisseur = nullptr;
  HRESULT hr = CoCreateInstance(CLSID_VaultaireProvider, nullptr, CLSCTX_INPROC_SERVER,
                                IID_ICredentialProvider, (void**)&fournisseur);
  Verifier(SUCCEEDED(hr) && fournisseur != nullptr,
           "CoCreateInstance(CLSID Vaultaire, ICredentialProvider) = 0x%08lx", (unsigned long)hr);
  return SUCCEEDED(hr) ? fournisseur : nullptr;
}

void PhaseFournisseur(ICredentialProvider* f) {
  Section("fournisseur : scenarios");

  // Les refus d'abord : un fournisseur qui a refusé un scénario doit encore
  // accepter le suivant — LogonUI réutilise le même objet.
  HRESULT hr = f->SetUsageScenario(CPUS_CHANGE_PASSWORD, 0);
  Verifier(hr == E_NOTIMPL, "SetUsageScenario(CHANGE_PASSWORD) refuse = 0x%08lx", (unsigned long)hr);
  hr = f->SetUsageScenario(CPUS_CREDUI, 0);
  Verifier(hr == E_NOTIMPL, "SetUsageScenario(CREDUI) refuse = 0x%08lx", (unsigned long)hr);
  hr = f->SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0);
  Verifier(hr == S_OK, "SetUsageScenario(UNLOCK_WORKSTATION) accepte = 0x%08lx", (unsigned long)hr);
  hr = f->SetUsageScenario(CPUS_LOGON, 0);
  Verifier(hr == S_OK, "SetUsageScenario(LOGON) accepte = 0x%08lx", (unsigned long)hr);

  // LogonUI passe la liste des comptes AVANT de demander les tuiles (TO-DO 157).
  Section("fournisseur : liste des comptes (ICredentialProviderSetUserArray)");
  ICredentialProviderSetUserArray* liste = nullptr;
  hr = f->QueryInterface(IID_ICredentialProviderSetUserArray, (void**)&liste);
  if (g_variantes) {
    Verifier(hr == E_NOINTERFACE && liste == nullptr,
             "variante ModeV1 : ICredentialProviderSetUserArray refusee = 0x%08lx", (unsigned long)hr);
  } else {
    Verifier(hr == S_OK && liste != nullptr, "QueryInterface(ICredentialProviderSetUserArray) = 0x%08lx",
             (unsigned long)hr);
  }
  if (liste != nullptr) {
    hr = liste->SetUserArray(&g_comptes);
    Verifier(hr == S_OK && g_comptes.references == 2, "SetUserArray = 0x%08lx, liste gardee (%ld ref.)",
             (unsigned long)hr, (long)g_comptes.references);
    liste->Release();
  }

  Section("fournisseur : description des champs");
  DWORD nombre = 0;
  hr = f->GetFieldDescriptorCount(&nombre);
  Verifier(hr == S_OK && nombre == kNombreDeChamps, "GetFieldDescriptorCount = %lu (attendu %lu)",
           (unsigned long)nombre, (unsigned long)kNombreDeChamps);

  for (DWORD i = 0; i < kNombreDeChamps; ++i) {
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* d = nullptr;
    hr = f->GetFieldDescriptorAt(i, &d);
    const bool bon = hr == S_OK && d != nullptr && d->dwFieldID == i && d->cpft == kTypes[i] &&
                     d->pszLabel != nullptr && IsEqualGUID(d->guidFieldType, *RoleAttendu(i));
    Verifier(bon, "GetFieldDescriptorAt(%lu) : rang, type %d, role, libelle \"%s\"", (unsigned long)i,
             d ? (int)d->cpft : -1, d ? Ascii(d->pszLabel).c_str() : "(nul)");
    // Libérés comme LogonUI les libère. Un libellé qui ne viendrait pas de
    // CoTaskMemAlloc ferait tomber LogonUI ici — wine le laisse parfois passer,
    // Windows jamais.
    if (d != nullptr) {
      CoTaskMemFree(d->pszLabel);
      CoTaskMemFree(d);
    }
  }
  CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* d = nullptr;
  hr = f->GetFieldDescriptorAt(kNombreDeChamps, &d);
  Verifier(hr == E_INVALIDARG && d == nullptr, "GetFieldDescriptorAt(hors borne) refuse = 0x%08lx",
           (unsigned long)hr);

  Section("fournisseur : tuiles");
  DWORD tuiles = 0, par_defaut = 99;
  BOOL auto_ouvrir = TRUE;
  hr = f->GetCredentialCount(&tuiles, &par_defaut, &auto_ouvrir);
  Verifier(hr == S_OK && tuiles == 1, "GetCredentialCount = %lu tuile(s)", (unsigned long)tuiles);
  if (g_variantes) {
    Verifier(par_defaut == 0, "variante TuileParDefaut : tuile par defaut = %lu", (unsigned long)par_defaut);
  } else {
    Verifier(par_defaut == CREDENTIAL_PROVIDER_NO_DEFAULT,
             "aucune tuile par defaut (CREDENTIAL_PROVIDER_NO_DEFAULT) = 0x%08lx", (unsigned long)par_defaut);
  }
  Verifier(auto_ouvrir == FALSE, "jamais d'ouverture automatique");

  ICredentialProviderCredential* t = nullptr;
  hr = f->GetCredentialAt(1, &t);
  Verifier(hr == E_INVALIDARG && t == nullptr, "GetCredentialAt(1) refuse = 0x%08lx", (unsigned long)hr);
}

// Lit un champ texte comme LogonUI : la DLL alloue, l'appelant libère.
std::wstring Lire(ICredentialProviderCredential* t, DWORD champ, HRESULT* hr) {
  wchar_t* valeur = nullptr;
  *hr = t->GetStringValue(champ, &valeur);
  std::wstring copie = (valeur != nullptr) ? valeur : L"";
  CoTaskMemFree(valeur);
  return copie;
}

void PhaseTuile(ICredentialProvider* f, Agent agent, Serveur* serveur) {
  char titre[64];
  snprintf(titre, sizeof(titre), "tuile, agent %s", NomAgent(agent));
  Section(titre);

  Verifier(Demarrer(serveur, agent), "agent simule demarre (%s)", NomAgent(agent));

  // Un nouveau scénario, donc une tuile neuve : rien ne reste de la phase
  // précédente.
  HRESULT hr = f->SetUsageScenario(CPUS_LOGON, 0);
  Verifier(hr == S_OK, "SetUsageScenario(LOGON) = 0x%08lx", (unsigned long)hr);

  ICredentialProviderCredential* t = nullptr;
  hr = f->GetCredentialAt(0, &t);
  Verifier(hr == S_OK && t != nullptr, "GetCredentialAt(0) = 0x%08lx", (unsigned long)hr);
  if (t == nullptr) {
    Arreter(serveur);
    return;
  }

  ICredentialProviderCredential2* t2 = nullptr;
  hr = t->QueryInterface(IID_ICredentialProviderCredential2, (void**)&t2);
  if (g_variantes) {
    Verifier(hr == E_NOINTERFACE && t2 == nullptr,
             "variante ModeV1 : ICredentialProviderCredential2 refusee = 0x%08lx", (unsigned long)hr);
  } else {
    Verifier(hr == S_OK && t2 != nullptr, "QueryInterface(ICredentialProviderCredential2) = 0x%08lx",
             (unsigned long)hr);
  }
  if (t2 != nullptr) {
    wchar_t* sid = (wchar_t*)1;
    hr = t2->GetUserSid(&sid);
    Verifier(hr == S_FALSE && sid == nullptr, "GetUserSid : aucun compte rattache = 0x%08lx",
             (unsigned long)hr);
    t2->Release();
  }

  CEvenements evenements;
  hr = t->Advise(&evenements);
  Verifier(hr == S_OK, "Advise = 0x%08lx", (unsigned long)hr);

  // SetSelected : LogonUI l'appelle à la sélection de la tuile — dès
  // l'affichage si elle est seule sous « Autre utilisateur », ou si la variante
  // TuileParDefaut est posée. C'est ici qu'un agent muet figeait l'écran
  // (TO-DO 156).
  BOOL auto_ouvrir = TRUE;
  DWORD debut = GetTickCount();
  hr = t->SetSelected(&auto_ouvrir);
  DWORD duree = GetTickCount() - debut;
  Verifier(hr == S_OK && auto_ouvrir == FALSE, "SetSelected = 0x%08lx", (unsigned long)hr);
  Verifier(duree < kBorneSetSelectedMs, "SetSelected rend la main en %lu ms (borne %lu)",
           (unsigned long)duree, (unsigned long)kBorneSetSelectedMs);

  const wchar_t* attendu = L"";
  switch (agent) {
    case Agent::kAbsent:    attendu = L"Service Vaultaire arrêté sur ce poste."; break;
    case Agent::kMuet:      attendu = L"Le service Vaultaire de ce poste ne répond pas."; break;
    case Agent::kRepondant: attendu = L"Raccordé au domaine."; break;
  }
  Verifier(Egal(evenements.chaines[kChampMessage].c_str(), attendu),
           "message pousse a l'ecran : \"%s\"", Ascii(evenements.chaines[kChampMessage].c_str()).c_str());

  // Ce que LogonUI lit ensuite pour dessiner la tuile.
  bool etats_bons = true;
  for (DWORD i = 0; i < kNombreDeChamps; ++i) {
    CREDENTIAL_PROVIDER_FIELD_STATE etat;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE interaction;
    if (t->GetFieldState(i, &etat, &interaction) != S_OK) etats_bons = false;
    if (i == kChampTitre && etat != CPFS_DISPLAY_IN_BOTH) etats_bons = false;
    if (i == kChampUtilisateur && interaction != CPFIS_FOCUSED) etats_bons = false;
    if (i == kChampImage && etat != (g_variantes ? CPFS_HIDDEN : CPFS_DISPLAY_IN_BOTH)) etats_bons = false;
    if (i == kChampLibelle && etat != CPFS_HIDDEN) etats_bons = false;
  }
  Verifier(etats_bons, "GetFieldState : huit champs, titre et image visibles partout, libelle masque, "
                       "focus sur l'identifiant");

  // L'image : un bitmap que l'appelant détruit, comme LogonUI.
  HBITMAP image = nullptr;
  hr = t->GetBitmapValue(kChampImage, &image);
  BITMAP infos = {};
  const bool image_lisible = image != nullptr && GetObjectW(image, sizeof(infos), &infos) == sizeof(infos);
  Verifier(hr == S_OK && image_lisible && infos.bmWidth == 128 && infos.bmHeight == 128,
           "GetBitmapValue(image) = 0x%08lx, %ldx%ld", (unsigned long)hr, (long)infos.bmWidth,
           (long)infos.bmHeight);
  if (image != nullptr) DeleteObject(image);
  image = nullptr;
  hr = t->GetBitmapValue(kChampTitre, &image);
  Verifier(hr == E_INVALIDARG && image == nullptr, "GetBitmapValue(titre) refuse = 0x%08lx", (unsigned long)hr);

  bool chaines_bonnes = true;
  for (DWORD i = 0; i < kNombreDeChamps; ++i) {
    if (kTypes[i] == CPFT_SUBMIT_BUTTON || kTypes[i] == CPFT_TILE_IMAGE) continue;
    HRESULT r;
    std::wstring v = Lire(t, i, &r);
    if (r != S_OK) chaines_bonnes = false;
    if (i == kChampTitre && v != L"Vaultaire") chaines_bonnes = false;
    if (i == kChampMessage && v != attendu) chaines_bonnes = false;
    if (i == kChampLibelle && v != L"Vaultaire") chaines_bonnes = false;
  }
  Verifier(chaines_bonnes, "GetStringValue : chaque champ texte rend une valeur liberable");

  DWORD adjacent = 99;
  hr = t->GetSubmitButtonValue(kChampValider, &adjacent);
  Verifier(hr == S_OK && adjacent == kChampCode, "GetSubmitButtonValue : bouton sous le code (champ %lu)",
           (unsigned long)adjacent);

  // Une soumission sans rien de saisi : un message, et SURTOUT pas de bloc.
  CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE reponse = CPGSR_RETURN_CREDENTIAL_FINISHED;
  CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION bloc;
  ZeroMemory(&bloc, sizeof(bloc));
  wchar_t* texte = nullptr;
  CREDENTIAL_PROVIDER_STATUS_ICON icone = CPSI_NONE;
  hr = t->GetSerialization(&reponse, &bloc, &texte, &icone);
  Verifier(hr == S_OK && reponse == CPGSR_NO_CREDENTIAL_NOT_FINISHED && icone == CPSI_WARNING &&
               texte != nullptr && bloc.rgbSerialization == nullptr,
           "GetSerialization sans saisie : avertissement, aucun bloc (\"%s\")", Ascii(texte).c_str());
  CoTaskMemFree(texte);
  texte = nullptr;

  hr = t->SetStringValue(kChampUtilisateur, kUtilisateur);
  HRESULT hr2 = t->SetStringValue(kChampMotDePasse, kMotDePasse);
  HRESULT hr3 = t->SetStringValue(kChampCode, kCode);
  HRESULT hr4 = t->SetStringValue(kChampTitre, L"x");
  Verifier(hr == S_OK && hr2 == S_OK && hr3 == S_OK, "SetStringValue sur les trois saisies");
  Verifier(hr4 == E_INVALIDARG, "SetStringValue sur le titre refuse = 0x%08lx", (unsigned long)hr4);

  {
    HRESULT r;
    std::wstring mdp = Lire(t, kChampMotDePasse, &r);
    std::wstring code = Lire(t, kChampCode, &r);
    Verifier(mdp.empty() && code.empty(), "mot de passe et code relus VIDES (jamais reaffiches)");
  }

  if (agent != Agent::kMuet) {
    // La soumission : l'agent absent ou refusant doit donner un refus NOMMÉ,
    // sans bloc d'ouverture de session.
    ZeroMemory(&bloc, sizeof(bloc));
    reponse = CPGSR_RETURN_CREDENTIAL_FINISHED;
    debut = GetTickCount();
    hr = t->GetSerialization(&reponse, &bloc, &texte, &icone);
    duree = GetTickCount() - debut;
    const wchar_t* refus = (agent == Agent::kAbsent) ? L"Le service Vaultaire ne tourne pas sur ce poste."
                                                     : L"Connexion refusée.";
    Verifier(hr == S_OK && reponse == CPGSR_NO_CREDENTIAL_NOT_FINISHED && icone == CPSI_ERROR &&
                 bloc.rgbSerialization == nullptr,
             "GetSerialization : refus, aucun bloc (reponse %d, icone %d)", (int)reponse, (int)icone);
    Verifier(Egal(texte, refus), "texte du refus : \"%s\"", Ascii(texte).c_str());
    Verifier(duree < kBorneImmediateMs, "refus rendu en %lu ms", (unsigned long)duree);
    CoTaskMemFree(texte);
    texte = nullptr;
    CoTaskMemFree(bloc.rgbSerialization);
  }

  if (agent == Agent::kRepondant) {
    // Ce que l'agent a reçu. La présence du champ « otp », même vide, est ce
    // qui dit au core qu'il parle à une tuile récente (TO-DO 95).
    bool etat_vu = false, auth_vue = false, otp_vu = false;
    for (const std::string& r : serveur->requetes) {
      if (r.find("\"type\":\"etat\"") != std::string::npos) etat_vu = true;
      if (r.find("\"type\":\"auth\"") != std::string::npos) {
        auth_vue = true;
        if (r.find("\"otp\":\"314159\"") != std::string::npos) otp_vu = true;
      }
    }
    Verifier(etat_vu, "l'agent a recu la question d'etat");
    Verifier(auth_vue && otp_vu, "l'agent a recu l'authentification, code compris");
  }

  // Le focus part : le mot de passe et le code s'effacent, à l'écran aussi.
  evenements.Oublier();
  hr = t->SetDeselected();
  Verifier(hr == S_OK && evenements.poussees[kChampMotDePasse] > 0 &&
               evenements.chaines[kChampMotDePasse].empty() &&
               evenements.poussees[kChampCode] > 0 && evenements.chaines[kChampCode].empty(),
           "SetDeselected efface le mot de passe et le code a l'ecran");

  hr = t->UnAdvise();
  Verifier(hr == S_OK && evenements.references == 0,
           "UnAdvise rend l'objet d'evenements (references restantes : %ld)", (long)evenements.references);

  t->Release();
  Arreter(serveur);
}

}  // namespace

int main(int argc, char** argv) {
  g_variantes = argc > 1 && strcmp(argv[1], "--variantes") == 0;
  printf("faux LogonUI - essai du Credential Provider Vaultaire (TO-DO 149)%s\n",
         g_variantes ? " - variantes d'essai posees (TO-DO 157)" : "");
  HANDLE chien = CreateThread(nullptr, 0, ChienDeGarde, nullptr, 0, nullptr);
  if (chien != nullptr) CloseHandle(chien);

  HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(hr)) {
    printf("  ECHEC  CoInitializeEx = 0x%08lx\n", (unsigned long)hr);
    return 1;
  }

  Section("activation par COM");
  ICredentialProvider* f = Activer();
  if (f == nullptr) {
    CoUninitialize();
    printf("\n%d controle(s), %d echec(s) - arret : le fournisseur ne s'active pas\n",
           g_controles, g_echecs);
    return g_echecs;
  }

  // La DLL est chargée par COM : on la retrouve pour ses points d'entrée.
  HMODULE dll = GetModuleHandleW(L"VaultaireCredentialProvider.dll");
  Verifier(dll != nullptr, "DLL chargee dans le processus sous son nom");
  FnGetClassObject get_class =
      dll ? (FnGetClassObject)(void*)GetProcAddress(dll, "DllGetClassObject") : nullptr;
  FnCanUnloadNow can_unload =
      dll ? (FnCanUnloadNow)(void*)GetProcAddress(dll, "DllCanUnloadNow") : nullptr;
  Verifier(get_class != nullptr && can_unload != nullptr,
           "points d'entree DllGetClassObject et DllCanUnloadNow exportes sans decoration");
  if (get_class != nullptr) {
    IClassFactory* autre = nullptr;
    hr = get_class(IID_ICredentialProvider, IID_IClassFactory, (void**)&autre);
    Verifier(hr == CLASS_E_CLASSNOTAVAILABLE && autre == nullptr,
             "DllGetClassObject(autre CLSID) refuse = 0x%08lx", (unsigned long)hr);
  }

  PhaseFournisseur(f);

  Serveur serveur;
  PhaseTuile(f, Agent::kAbsent, &serveur);
  PhaseTuile(f, Agent::kMuet, &serveur);
  PhaseTuile(f, Agent::kRepondant, &serveur);

  Section("liberation");
  ULONG restantes = f->Release();
  Verifier(restantes == 0, "le fournisseur se libere (references restantes : %lu)", (unsigned long)restantes);
  Verifier(g_comptes.references == 1, "la liste des comptes est rendue (%ld ref.)", (long)g_comptes.references);
  // Le compte d'objets du module : sans lui, DllCanUnloadNow dit « encore
  // utilisée » pour toujours, et COM ne décharge jamais la DLL.
  if (can_unload != nullptr) {
    hr = can_unload();
    Verifier(hr == S_OK, "DllCanUnloadNow apres liberation = 0x%08lx (S_OK attendu)", (unsigned long)hr);
  }

  CoUninitialize();
  printf("\n%d controle(s), %d echec(s)\n", g_controles, g_echecs);
  return g_echecs;
}
