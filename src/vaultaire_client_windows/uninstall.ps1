# =====================================================================
# uninstall.ps1 — retirer l'agent Vaultaire d'un poste Windows
# =====================================================================
#
# L'ordre compte : le Credential Provider d'abord, l'agent ensuite.
#
# Une tuile enregistrée dont le service est arrêté affiche « service
# indisponible » à chaque tentative — c'est-à-dire qu'elle ne sert plus à rien
# mais reste la première chose que voit l'utilisateur.
#
#     .\uninstall.ps1                                # tout
#     .\uninstall.ps1 -CredentialProviderSeulement   # rendre l'écran de connexion
#     .\uninstall.ps1 -EffacerEtat                   # + identité, config, journaux

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$Racine = "C:\ProgramData\Vaultaire",
    [switch]$CredentialProviderSeulement,
    [switch]$EffacerEtat
)

$ErrorActionPreference = "Continue"
$Bin = Join-Path $Racine "bin"
$Service = "VaultaireAgent"

function Info($texte) { Write-Host "    $texte" }

# --- 1. L'écran de connexion, d'abord --------------------------------------
$dll = Join-Path $Bin "VaultaireCredentialProvider.dll"
$dllPresente = Test-Path $dll
if ($dllPresente) {
    # Start-Process -Wait, comme dans install.ps1 : regsvr32 est une application
    # graphique, « & regsvr32 » rend la main avant qu'il ait fini — et la DLL est
    # supprimée quelques lignes plus bas.
    Start-Process -FilePath regsvr32.exe -ArgumentList '/u', '/s', "`"$dll`"" -Wait | Out-Null
}

# Puis le registre, DIRECTEMENT — que la DLL soit là ou non.
#
# Le retrait ne reposait que sur regsvr32 /u, donc sur la DLL : une DLL effacée
# à la main, ou qui ne se charge plus, laissait ses clés en place et ce script
# annonçait « aucun Credential Provider enregistré ».
#
# « { » est le nom sous lequel s'inscrivaient les DLL d'avant le TO-DO 140, qui
# tronquaient leur GUID au premier caractère. Ces clés sont sans effet sur
# l'écran de connexion, mais elles restent sur les postes déjà installés.
#
# Une clé n'est retirée que si elle porte le LIBELLÉ de Vaultaire : on n'efface
# pas un sous-arbre de HKLM sur la foi de son seul nom.
$libelleCP = "Vaultaire Credential Provider"
$clesRetirees = 0
foreach ($id in @("{6F2A1B74-3C58-4E0A-9D21-7B4F8C0E5A93}", "{")) {
    foreach ($racineCle in @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers",
        "HKLM:\SOFTWARE\Classes\CLSID")) {
        $cle = "$racineCle\$id"
        if (-not (Test-Path -LiteralPath $cle)) { continue }
        $libelle = (Get-ItemProperty -LiteralPath $cle -ErrorAction SilentlyContinue).'(default)'
        if ($libelle -ne $libelleCP) {
            Info "clé laissée en place, elle ne porte pas le libellé Vaultaire : $cle"
            continue
        }
        Remove-Item -LiteralPath $cle -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $cle) {
            Info "clé NON retirée (droits ?) : $cle"
        } else {
            $clesRetirees++
            Info "clé retirée : $cle"
        }
    }
}

if ($dllPresente -or $clesRetirees -gt 0) {
    Info "Credential Provider retiré de l'écran de connexion"
} else {
    Info "aucun Credential Provider enregistré"
}

if ($CredentialProviderSeulement) {
    Info "l'agent continue de tourner ; vaultaire_login.exe reste utilisable"
    exit 0
}

# --- 2. Le service ---------------------------------------------------------
if (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
    Stop-Service $Service -Force -ErrorAction SilentlyContinue
    sc.exe delete $Service | Out-Null
    Info "service $Service supprimé"
}

Start-Sleep -Seconds 1
if (Test-Path $dll) { Remove-Item $dll -Force -ErrorAction SilentlyContinue }
foreach ($fichier in @("vaultaire_client_windows.exe", "vaultaire_login.exe")) {
    $chemin = Join-Path $Bin $fichier
    if (Test-Path $chemin) { Remove-Item $chemin -Force -ErrorAction SilentlyContinue }
}
Info "binaires retirés"

# --- 3. L'état, seulement si on le demande ---------------------------------
#
# Il porte l'identité de la machine : l'effacer oblige à en recréer une sur le
# core (`vlt create -c`), l'ancienne restant dans la base comme un fantôme.
if ($EffacerEtat) {
    Remove-Item $Racine -Recurse -Force -ErrorAction SilentlyContinue
    Info "état effacé : $Racine"
    Info "pensez à retirer la machine côté core (vlt delete -c <id>)"
} else {
    Info "état CONSERVÉ dans $Racine (identité, configuration, journaux)"
    Info "  pour tout effacer : .\uninstall.ps1 -EffacerEtat"
}

# --- 4. Les comptes locaux provisionnés ------------------------------------
#
# Ils ne sont PAS supprimés, et c'est délibéré : ils portent les profils, les
# documents et les droits des utilisateurs qui se sont connectés. Les effacer
# avec l'agent ferait disparaître des données que personne n'a demandé à perdre.
$comptes = Get-LocalUser | Where-Object { $_.Description -like "*Vaultaire*" }
if ($comptes) {
    Info ""
    Info "$($comptes.Count) compte(s) local(aux) créé(s) par Vaultaire, CONSERVÉ(S) :"
    $comptes | ForEach-Object { Info "  $($_.Name)" }
    Info "  Ils gardent leur profil et leur dernier mot de passe connu."
    Info "  Pour en retirer un : Remove-LocalUser -Name <nom>"
}
