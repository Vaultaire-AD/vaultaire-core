#include "vaultaire_credential.h"
#include "vaultaire_guid.h"
#include "vaultaire_kerb.h"
#include "vaultaire_pipe.h"

#include <new>

namespace vaultaire {
namespace {

// Description des champs. L'ordre suit l'énumération Champ.
// guidFieldType est posé explicitement à GUID_NULL : aucun de ces champs n'a de
// rôle connu de Windows (le champ « nom d'utilisateur » d'une tuile rattachée à
// un compte, par exemple). Le laisser non initialisé enverrait à Winlogon les
// octets qui traînent en mémoire.
const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR kChamps[kNombreDeChamps] = {
    {kChampTitre,       CPFT_LARGE_TEXT,    const_cast<wchar_t*>(L"Vaultaire"),           GUID_NULL},
    {kChampUtilisateur, CPFT_EDIT_TEXT,     const_cast<wchar_t*>(L"Utilisateur@domaine"), GUID_NULL},
    {kChampMotDePasse,  CPFT_PASSWORD_TEXT, const_cast<wchar_t*>(L"Mot de passe"),        GUID_NULL},
    // Le libellé dit QUOI TAPER quand on n'a pas de second facteur. Sans cette
    // précision, la majorité des utilisateurs — qui n'en ont pas — voit un
    // champ qu'elle ne comprend pas, à chaque connexion.
    {kChampCode,        CPFT_PASSWORD_TEXT, const_cast<wchar_t*>(L"Code a 6 chiffres (0000 si vous n'en avez pas)"), GUID_NULL},
    {kChampValider,     CPFT_SUBMIT_BUTTON, const_cast<wchar_t*>(L"Se connecter"),        GUID_NULL},
    {kChampMessage,     CPFT_SMALL_TEXT,    const_cast<wchar_t*>(L""),                    GUID_NULL},
};

// Copier duplique une chaîne dans la mémoire que Windows libérera.
HRESULT Copier(const std::wstring& source, wchar_t** sortie) {
  const size_t octets = (source.size() + 1) * sizeof(wchar_t);
  *sortie = (wchar_t*)CoTaskMemAlloc(octets);
  if (*sortie == nullptr) return E_OUTOFMEMORY;
  CopyMemory(*sortie, source.c_str(), octets);
  return S_OK;
}

}  // namespace

const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* DescriptionDesChamps() { return kChamps; }

CVaultaireCredential::CVaultaireCredential()
    : references_(1), scenario_(CPUS_LOGON), evenements_(nullptr) {}

CVaultaireCredential::~CVaultaireCredential() {
  EffacerMotDePasse();
  EffacerCode();
}

// EffacerMotDePasse écrase la mémoire, et ne se contente pas de vider la chaîne.
//
// `mot_de_passe_.clear()` laisse les octets en place dans le tampon de la
// chaîne : ils resteraient lisibles dans la mémoire de LogonUI, qui vit aussi
// longtemps que la session de connexion.
void CVaultaireCredential::EffacerMotDePasse() {
  if (!mot_de_passe_.empty()) {
    SecureZeroMemory(&mot_de_passe_[0], mot_de_passe_.size() * sizeof(wchar_t));
  }
  mot_de_passe_.clear();
}

// EffacerCode : même raisonnement que pour le mot de passe.
//
// Un code TOTP n'est pas un secret durable — il vaut 90 secondes au plus — mais
// 90 secondes suffisent largement à qui lit la mémoire d'un processus, et
// l'anti-rejeu ne protège que d'un SECOND usage : le premier reste possible.
void CVaultaireCredential::EffacerCode() {
  if (!code_.empty()) {
    SecureZeroMemory(&code_[0], code_.size() * sizeof(wchar_t));
  }
  code_.clear();
}

HRESULT CVaultaireCredential::Initialiser(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario) {
  scenario_ = scenario;
  return S_OK;
}

IFACEMETHODIMP CVaultaireCredential::QueryInterface(REFIID riid, void** ppv) {
  if (ppv == nullptr) return E_POINTER;
  if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential ||
      riid == IID_ICredentialProviderCredential2) {
    *ppv = static_cast<ICredentialProviderCredential2*>(this);
    AddRef();
    return S_OK;
  }
  *ppv = nullptr;
  return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) CVaultaireCredential::AddRef() { return InterlockedIncrement(&references_); }

IFACEMETHODIMP_(ULONG) CVaultaireCredential::Release() {
  LONG restantes = InterlockedDecrement(&references_);
  if (restantes == 0) delete this;
  return restantes;
}

IFACEMETHODIMP CVaultaireCredential::Advise(ICredentialProviderCredentialEvents* evenements) {
  if (evenements_ != nullptr) evenements_->Release();
  evenements_ = evenements;
  if (evenements_ != nullptr) evenements_->AddRef();
  return S_OK;
}

IFACEMETHODIMP CVaultaireCredential::UnAdvise() {
  if (evenements_ != nullptr) {
    evenements_->Release();
    evenements_ = nullptr;
  }
  return S_OK;
}

// SetSelected : l'utilisateur vient de cliquer sur la tuile.
//
// C'est ici qu'on demande son état à l'agent. Le faire MAINTENANT, et non au
// clic sur « Se connecter », permet d'annoncer « service indisponible » avant
// la saisie — plutôt que de faire taper un mot de passe pour rien.
IFACEMETHODIMP CVaultaireCredential::SetSelected(BOOL* auto_ouvrir) {
  *auto_ouvrir = FALSE;

  Reponse etat = Etat();
  switch (etat.statut) {
    case Statut::kSucces:
      message_ = etat.raccorde ? L"Raccordé au domaine."
                               : L"Agent démarré, aucun core joignable pour l'instant.";
      break;
    case Statut::kAgentAbsent:
      message_ = L"Service Vaultaire arrêté sur ce poste.";
      break;
    default:
      message_ = L"Service Vaultaire indisponible.";
  }
  if (evenements_ != nullptr) {
    evenements_->SetFieldString(this, kChampMessage, message_.c_str());
  }
  return S_OK;
}

// SetDeselected : la tuile perd le focus. Le mot de passe part avec.
IFACEMETHODIMP CVaultaireCredential::SetDeselected() {
  EffacerMotDePasse();
  EffacerCode();
  if (evenements_ != nullptr) {
    evenements_->SetFieldString(this, kChampMotDePasse, L"");
    evenements_->SetFieldString(this, kChampCode, L"");
  }
  return S_OK;
}

IFACEMETHODIMP CVaultaireCredential::GetFieldState(
    DWORD champ, CREDENTIAL_PROVIDER_FIELD_STATE* etat,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interaction) {
  if (champ >= kNombreDeChamps || etat == nullptr || interaction == nullptr) return E_INVALIDARG;

  *etat = CPFS_DISPLAY_IN_SELECTED_TILE;
  *interaction = CPFIS_NONE;
  switch (champ) {
    case kChampTitre:
      *etat = CPFS_DISPLAY_IN_BOTH;
      break;
    case kChampUtilisateur:
      *interaction = CPFIS_FOCUSED;
      break;
    case kChampMotDePasse:
    case kChampCode:
      *interaction = CPFIS_NONE;
      break;
    default:
      break;
  }
  return S_OK;
}

IFACEMETHODIMP CVaultaireCredential::GetStringValue(DWORD champ, wchar_t** valeur) {
  if (champ >= kNombreDeChamps || valeur == nullptr) return E_INVALIDARG;
  switch (champ) {
    case kChampTitre:       return Copier(L"Vaultaire", valeur);
    case kChampUtilisateur: return Copier(utilisateur_, valeur);
    // Rendus VIDES, comme le mot de passe : Windows redemande la valeur à
    // chaque affichage, et la lui rendre reviendrait à la réafficher.
    case kChampMotDePasse:  return Copier(L"", valeur);
    case kChampCode:        return Copier(L"", valeur);
    case kChampValider:     return Copier(L"Se connecter", valeur);
    case kChampMessage:     return Copier(message_, valeur);
    default:                return E_INVALIDARG;
  }
}

IFACEMETHODIMP CVaultaireCredential::GetBitmapValue(DWORD, HBITMAP*) { return E_NOTIMPL; }
IFACEMETHODIMP CVaultaireCredential::GetCheckboxValue(DWORD, BOOL*, wchar_t**) { return E_NOTIMPL; }
IFACEMETHODIMP CVaultaireCredential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_NOTIMPL; }
IFACEMETHODIMP CVaultaireCredential::GetComboBoxValueAt(DWORD, DWORD, wchar_t**) { return E_NOTIMPL; }
IFACEMETHODIMP CVaultaireCredential::SetCheckboxValue(DWORD, BOOL) { return E_NOTIMPL; }
IFACEMETHODIMP CVaultaireCredential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }
IFACEMETHODIMP CVaultaireCredential::CommandLinkClicked(DWORD) { return E_NOTIMPL; }

IFACEMETHODIMP CVaultaireCredential::GetSubmitButtonValue(DWORD champ, DWORD* champ_adjacent) {
  if (champ != kChampValider || champ_adjacent == nullptr) return E_INVALIDARG;
  // Le bouton se place sous le DERNIER champ de saisie : c'est ce qui fait
  // valider avec la touche Entrée. Depuis le second facteur (TO-DO 95), ce
  // dernier champ est le code et non le mot de passe — le laisser sur le mot de
  // passe ferait valider une saisie incomplète.
  *champ_adjacent = kChampCode;
  return S_OK;
}

IFACEMETHODIMP CVaultaireCredential::SetStringValue(DWORD champ, const wchar_t* valeur) {
  switch (champ) {
    case kChampUtilisateur:
      utilisateur_ = (valeur != nullptr) ? valeur : L"";
      return S_OK;
    case kChampMotDePasse:
      EffacerMotDePasse();
      mot_de_passe_ = (valeur != nullptr) ? valeur : L"";
      return S_OK;
    case kChampCode:
      EffacerCode();
      code_ = (valeur != nullptr) ? valeur : L"";
      return S_OK;
    default:
      return E_INVALIDARG;
  }
}

IFACEMETHODIMP CVaultaireCredential::GetUserSid(wchar_t** sid) {
  // Aucune tuile rattachée à un compte existant : c'est ce que dit
  // S_FALSE avec un SID nul. Rendre un SID ferait apparaître Vaultaire comme
  // une méthode de connexion d'un compte local précis, alors que le compte est
  // choisi par l'identifiant tapé.
  *sid = nullptr;
  return S_FALSE;
}

// GetSerialization : le clic sur « Se connecter ».
//
// Tout se joue ici, dans cet ordre :
//
//  1. on demande le verdict à l'agent (qui interroge le core et provisionne le
//     compte local) ;
//  2. sur acceptation, on rend à Windows un bloc d'ouverture de session
//     ORDINAIRE, pour le compte local que l'agent vient de préparer ;
//  3. sur refus, on rend un message et RIEN d'autre — surtout pas un bloc.
IFACEMETHODIMP CVaultaireCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* reponse,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialisation,
    wchar_t** texte_erreur, CREDENTIAL_PROVIDER_STATUS_ICON* icone) {
  *reponse = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
  *texte_erreur = nullptr;
  *icone = CPSI_NONE;

  if (utilisateur_.empty() || mot_de_passe_.empty()) {
    *icone = CPSI_WARNING;
    return Copier(L"Renseignez l'identifiant et le mot de passe.", texte_erreur);
  }
  // Le code est EXIGÉ ici, et le message dit quoi taper quand on n'en a pas.
  //
  // Envoyer un champ vide serait pire que de refuser : le core n'aurait aucun
  // moyen de distinguer « agent ancien » de « l'utilisateur n'a rien tapé », et
  // c'est précisément cette distinction qui porte la migration (TO-DO 95).
  if (code_.empty()) {
    *icone = CPSI_WARNING;
    return Copier(L"Renseignez le code. Tapez 0000 si vous n'avez pas de second facteur.",
                  texte_erreur);
  }

  Reponse verdict = Authentifier(utilisateur_, mot_de_passe_, code_);

  if (verdict.statut != Statut::kSucces) {
    const wchar_t* texte = L"Connexion refusée.";
    switch (verdict.statut) {
      case Statut::kIndisponible:
        texte = L"Aucun serveur Vaultaire joignable depuis ce poste.";
        break;
      case Statut::kDelai:
        texte = L"Le serveur Vaultaire n'a pas répondu.";
        break;
      case Statut::kAgentAbsent:
        texte = L"Le service Vaultaire ne tourne pas sur ce poste.";
        break;
      case Statut::kErreurLocale:
        texte = L"Erreur locale du service Vaultaire (voir son journal).";
        break;
      default:
        break;
    }
    Journaliser(L"refus pour %s (statut %d)", utilisateur_.c_str(), (int)verdict.statut);
    EffacerMotDePasse();
    // Le code aussi : un code refusé reste valide quelques dizaines de secondes,
    // et l'anti-rejeu ne protège que d'un SECOND usage réussi.
    EffacerCode();
    *icone = CPSI_ERROR;
    return Copier(texte, texte_erreur);
  }

  if (verdict.compte_local.empty()) {
    // Acceptation sans compte local : l'agent n'a rien provisionné, il n'y a
    // donc personne à qui ouvrir la session. Mieux vaut le dire que rendre un
    // bloc que Windows refusera ensuite sans expliquer pourquoi.
    Journaliser(L"acceptation sans compte local pour %s", utilisateur_.c_str());
    EffacerMotDePasse();
    EffacerCode();
    *icone = CPSI_ERROR;
    return Copier(L"Compte local indisponible sur ce poste.", texte_erreur);
  }

  HRESULT hr = PreparerBlocOuverture(scenario_, NomDeCetteMachine(),
                                     verdict.compte_local, mot_de_passe_, serialisation);
  EffacerMotDePasse();
  if (FAILED(hr)) {
    *icone = CPSI_ERROR;
    Journaliser(L"sérialisation impossible (0x%08lx)", hr);
    return Copier(L"Préparation de la session impossible.", texte_erreur);
  }

  serialisation->clsidCredentialProvider = CLSID_VaultaireProvider;
  *reponse = CPGSR_RETURN_CREDENTIAL_FINISHED;
  Journaliser(L"session ouverte pour %s (compte local %s)", utilisateur_.c_str(),
              verdict.compte_local.c_str());
  return S_OK;
}

// ReportResult : Windows dit ce qu'il a fait du bloc.
//
// C'est le seul endroit d'où l'on apprend qu'une ouverture de session a échoué
// APRÈS le fournisseur — mot de passe refusé par LSA, compte désactivé, droit
// d'ouverture de session interactive absent. Sans ce journal, l'agent dirait
// « accepté » et l'écran reviendrait à la case départ sans explication.
IFACEMETHODIMP CVaultaireCredential::ReportResult(NTSTATUS etat, NTSTATUS sous_etat,
                                                  wchar_t** texte_erreur,
                                                  CREDENTIAL_PROVIDER_STATUS_ICON* icone) {
  *texte_erreur = nullptr;
  *icone = CPSI_NONE;
  if (etat != 0) {
    Journaliser(L"Windows a refusé l'ouverture de session (0x%08lx / 0x%08lx)",
                (unsigned long)etat, (unsigned long)sous_etat);
  }
  return S_OK;
}

}  // namespace vaultaire
