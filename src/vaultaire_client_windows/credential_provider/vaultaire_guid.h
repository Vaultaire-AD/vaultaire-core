// L'identifiant COM du fournisseur.
//
// Windows range les Credential Providers par CLSID sous
// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers.
// Ce GUID est donc l'IDENTITÉ de Vaultaire à l'écran de connexion : il est tiré
// une fois et ne change plus. Le changer ferait cohabiter deux tuiles après une
// mise à jour, l'ancienne pointant sur une DLL désinstallée.

#pragma once

#include <initguid.h>

// {6F2A1B74-3C58-4E0A-9D21-7B4F8C0E5A93}
DEFINE_GUID(CLSID_VaultaireProvider,
            0x6f2a1b74, 0x3c58, 0x4e0a, 0x9d, 0x21, 0x7b, 0x4f, 0x8c, 0x0e, 0x5a, 0x93);

// Le libellé affiché dans le registre, pour qu'un administrateur qui liste les
// fournisseurs sache lequel est celui-ci.
#define VAULTAIRE_CP_NOM L"Vaultaire Credential Provider"
