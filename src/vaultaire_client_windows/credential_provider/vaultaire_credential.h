// La TUILE de l'écran de connexion : ses champs, et ce qui se passe au clic.

#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <string>

namespace vaultaire {

// Les champs de la tuile, dans l'ordre où Windows les affiche.
//
// L'ordre EST l'interface : Winlogon les identifie par leur rang, et insérer un
// champ au milieu décale tout ce qui suit — le mot de passe se retrouverait lu
// comme un nom d'utilisateur.
enum Champ {
  kChampTitre = 0,      // « Vaultaire », grand texte
  kChampUtilisateur,    // saisie : alice@domaine.fr
  kChampMotDePasse,     // saisie masquée
  // Second facteur (TO-DO 95). Saisie masquée elle aussi : un code TOTP reste
  // valide jusqu'à 90 secondes, assez pour que quelqu'un qui regarde l'écran
  // s'en serve. L'ordre place ce champ APRÈS le mot de passe — et avant le
  // bouton — parce que c'est l'ordre dans lequel on le saisit.
  kChampCode,
  kChampValider,        // bouton
  kChampMessage,        // petit texte : état de l'agent, motif d'un refus
  kNombreDeChamps,
};

class CVaultaireCredential : public ICredentialProviderCredential2 {
 public:
  CVaultaireCredential();

  HRESULT Initialiser(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario);

  // IUnknown
  IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
  IFACEMETHODIMP_(ULONG) AddRef() override;
  IFACEMETHODIMP_(ULONG) Release() override;

  // ICredentialProviderCredential
  IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* evenements) override;
  IFACEMETHODIMP UnAdvise() override;
  IFACEMETHODIMP SetSelected(BOOL* auto_ouvrir) override;
  IFACEMETHODIMP SetDeselected() override;
  IFACEMETHODIMP GetFieldState(DWORD champ,
                               CREDENTIAL_PROVIDER_FIELD_STATE* etat,
                               CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interaction) override;
  IFACEMETHODIMP GetStringValue(DWORD champ, wchar_t** valeur) override;
  IFACEMETHODIMP GetBitmapValue(DWORD champ, HBITMAP* image) override;
  IFACEMETHODIMP GetCheckboxValue(DWORD champ, BOOL* coche, wchar_t** libelle) override;
  IFACEMETHODIMP GetSubmitButtonValue(DWORD champ, DWORD* champ_adjacent) override;
  IFACEMETHODIMP GetComboBoxValueCount(DWORD champ, DWORD* nombre, DWORD* selection) override;
  IFACEMETHODIMP GetComboBoxValueAt(DWORD champ, DWORD element, wchar_t** valeur) override;
  IFACEMETHODIMP SetStringValue(DWORD champ, const wchar_t* valeur) override;
  IFACEMETHODIMP SetCheckboxValue(DWORD champ, BOOL coche) override;
  IFACEMETHODIMP SetComboBoxSelectedValue(DWORD champ, DWORD element) override;
  IFACEMETHODIMP CommandLinkClicked(DWORD champ) override;
  IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* reponse,
                                  CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialisation,
                                  wchar_t** texte_erreur,
                                  CREDENTIAL_PROVIDER_STATUS_ICON* icone) override;
  IFACEMETHODIMP ReportResult(NTSTATUS etat, NTSTATUS sous_etat,
                              wchar_t** texte_erreur,
                              CREDENTIAL_PROVIDER_STATUS_ICON* icone) override;

  // ICredentialProviderCredential2
  IFACEMETHODIMP GetUserSid(wchar_t** sid) override;

 private:
  // Destructeur VIRTUEL : l'objet est détruit par « delete this » depuis
  // Release(), à travers un pointeur d'interface. Sans virtual, seul le
  // destructeur de base tournerait — le mot de passe ne serait pas effacé.
  virtual ~CVaultaireCredential();
  void EffacerMotDePasse();
  // Même traitement que le mot de passe : un code reste valide jusqu'à 90
  // secondes, il ne doit pas traîner dans la mémoire de LogonUI.
  void EffacerCode();

  LONG references_;
  CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
  ICredentialProviderCredentialEvents* evenements_;

  std::wstring utilisateur_;
  std::wstring mot_de_passe_;
  std::wstring code_;
  std::wstring message_;
};

}  // namespace vaultaire
