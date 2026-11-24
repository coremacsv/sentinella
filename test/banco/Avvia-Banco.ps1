# =====================================================================
#  Avvia il banco di prova di Sentinella in Windows Sandbox.
#
#  La Sandbox e' una copia di Windows usa e getta: le tracce finte
#  vengono piazzate li' dentro, mai sul tuo PC, e alla chiusura della
#  finestra sparisce tutto. Rete disattivata, cartella di Sentinella
#  montata in sola lettura: il banco puo' scrivere solo i risultati.
#
#  Uso:  powershell -ExecutionPolicy Bypass -File test\banco\Avvia-Banco.ps1 [-Modo Lampo]
#  Serve la funzionalita' "Windows Sandbox" (Windows 10/11 Pro).
# =====================================================================
param([ValidateSet('Lampo', 'Rapida')][string]$Modo = 'Rapida', [int]$MinutiMassimi = 40)

$radice = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$risultati = Join-Path $PSScriptRoot 'risultati'
$sandbox = "$env:SystemRoot\System32\WindowsSandbox.exe"
if (-not (Test-Path $sandbox)) {
    Write-Host "Windows Sandbox non e' attiva su questo PC." -ForegroundColor Red
    Write-Host "Attivala da: Pannello di controllo > Programmi > Attiva o disattiva funzionalita' di Windows > Windows Sandbox, poi riavvia." -ForegroundColor Yellow
    exit 1
}
if (Get-Process WindowsSandbox*, WindowsSandboxClient* -ErrorAction SilentlyContinue) {
    Write-Host "C'e' gia' una Sandbox aperta: chiudila prima (se ne puo' aprire una sola)." -ForegroundColor Red
    exit 1
}
New-Item -ItemType Directory -Path $risultati -Force | Out-Null
Remove-Item (Join-Path $risultati 'banco-finito.txt'), (Join-Path $risultati 'banco-in-corso.log') -ErrorAction SilentlyContinue

$wsb = Join-Path $risultati 'banco.wsb'
@"
<Configuration>
  <Networking>Disable</Networking>
  <MappedFolders>
    <MappedFolder><HostFolder>$radice</HostFolder><SandboxFolder>C:\Sentinella</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$risultati</HostFolder><SandboxFolder>C:\Risultati</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Sentinella\test\banco\Banco-di-prova.ps1 -Modo $Modo</Command>
  </LogonCommand>
</Configuration>
"@ | Out-File $wsb -Encoding utf8

Write-Host "Avvio Windows Sandbox (modalita' $Modo). Non chiudere la finestra della Sandbox finche' non ho finito." -ForegroundColor Cyan
Start-Process $sandbox -ArgumentList "`"$wsb`""
$fine = (Get-Date).AddMinutes($MinutiMassimi)
$segnale = Join-Path $risultati 'banco-finito.txt'
while (-not (Test-Path $segnale) -and (Get-Date) -lt $fine) { Start-Sleep 10 }
if (-not (Test-Path $segnale)) {
    Write-Host "Il banco non ha finito entro $MinutiMassimi minuti. Guarda $risultati\banco-in-corso.log" -ForegroundColor Red
    exit 2
}
$nome = (Get-Content $segnale).Trim()
Write-Host ""
Get-Content (Join-Path $risultati "$nome.md")
Write-Host ""
Write-Host "Risultati in $risultati. Ora puoi chiudere la Sandbox: tutto quello che c'era dentro sparisce." -ForegroundColor Green
