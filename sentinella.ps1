# =====================================================================
#
#   SENTINELLA  -  sicurezza e salute del tuo PC
#   Versione 3.0  -  by lozy
#
#   Uno strumento unico che risponde a due domande:
#     "Il mio PC e' infetto?"  e  "Il mio PC sta bene?"
#
#   SOLA LETTURA: non cancella, non modifica, non installa nulla.
#   Le uniche azioni attive sono la scansione di Windows Defender e
#   'sfc /verifyonly', entrambi strumenti Microsoft che si limitano
#   a verificare. La scansione offline di Defender (che riavvia il PC)
#   parte solo se la chiedi scrivendo RIAVVIA.
#
#   Nato dopo una vera infezione da infostealer, in cui l'antivirus
#   non aveva rilevato nulla e il file infetto era sopravvissuto alla
#   formattazione perche' si trovava su un secondo disco.
#
#   Struttura:
#     sentinella.ps1        questo file: menu, ordine dei controlli
#     moduli\Base.ps1       motore dei controlli e funzioni di output
#     moduli\Analisi.ps1    logica di giudizio (provata in test\)
#     moduli\*.ps1          un file per ogni parte della scansione
#
#   Uso senza domande (es. attivita' pianificata):
#     powershell -File sentinella.ps1 -Modo Lampo -Silenzioso
#   Codice di uscita: 0 tutto regolare, 1 da guardare, 2 grave,
#                     3 nessun problema ma controlli non verificati
#
# =====================================================================
[CmdletBinding()]
param(
    [ValidateSet('Lampo', 'Rapida', 'Completa')]
    [string]$Modo,
    [switch]$Silenzioso
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$VERSIONE = '3.0'
$silenzioso = [bool]$Silenzioso
if ($silenzioso -and -not $Modo) { $Modo = 'Lampo' }
$cartellaSentinella = $PSScriptRoot
$inizio = Get-Date
$TOTPASSI = 0

foreach ($m in @('Base', 'Analisi', 'Sistema', 'Integrita', 'Sicurezza', 'Infostealer', 'Salute', 'Antivirus', 'Confronto', 'Report')) {
    $f = Join-Path $cartellaSentinella "moduli\$m.ps1"
    if (-not (Test-Path -LiteralPath $f)) {
        Write-Host ""
        Write-Host "  ERRORE: manca il file moduli\$m.ps1" -ForegroundColor Red
        Write-Host "  Sentinella ha bisogno di tutta la cartella 'moduli' accanto a sentinella.ps1." -ForegroundColor Red
        if (-not $silenzioso) { Read-Host "  Premi INVIO per chiudere" }
        exit 4
    }
    . $f
}

# Senza questo i caratteri a blocchi escono come punti interrogativi.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# =============================================================== MENU
function Larghezza {
    $w = 100
    try { $w = $Host.UI.RawUI.WindowSize.Width } catch { $w = 100 }
    if (-not $w -or $w -lt 40) { $w = 80 }
    return $w
}
# La firma dell'autore va allineata al bordo destro dell'insegna, come
# negli strumenti da riga di comando: presente ma senza rubare la scena.
function Firma([int]$bordoDestro) {
    $testo = '~ by lozy ~'
    $pad = $bordoDestro - $testo.Length
    if ($pad -lt 0) { $pad = 0 }
    Write-Host (" " * $pad) -NoNewline
    Write-Host '~ ' -NoNewline -ForegroundColor DarkGray
    Write-Host 'by ' -NoNewline -ForegroundColor DarkGray
    Write-Host 'lozy' -NoNewline -ForegroundColor Cyan
    Write-Host ' ~' -ForegroundColor DarkGray
}
function Insegna {
    $w = Larghezza
    $arte = @(
        '███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗      █████╗ ',
        '██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██║     ██╔══██╗',
        '███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ██║     ███████║',
        '╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██║     ██╔══██║',
        '███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗███████╗██║  ██║',
        '╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝'
    )
    # Gradiente monotono chiaro->scuro dall'alto in basso.
    $colori = @('Cyan','Cyan','DarkCyan','DarkCyan','Blue','DarkBlue')
    # La vespa: SOLO caratteri del blocco CP437 (mattoni/mezzi mattoni),
    # niente diagonali: il terminale le disegnerebbe con un font diverso.
    $vespa = @(
        '    \  /    ',
        '   ██████   ',
        '  ████████  ',
        '  ████████  ',
        '  ████████  ',
        '     vv     '
    )
    $coloriVespa = @('White','White','White','DarkBlue','DarkYellow','DarkYellow')
    # Servono circa 100 colonne per vespa e scritta affiancate; sotto quella
    # soglia si toglie prima la vespa, poi si passa alla versione compatta.
    if ($w -ge 100) {
        Write-Host ""
        for ($i = 0; $i -lt $arte.Count; $i++) {
            Write-Host ("  " + $vespa[$i] + "  ") -NoNewline -ForegroundColor $coloriVespa[$i]
            Write-Host $arte[$i] -ForegroundColor $colori[$i]
        }
        Firma 96
    } elseif ($w -ge 84) {
        Write-Host ""
        for ($i = 0; $i -lt $arte.Count; $i++) { Write-Host ("  " + $arte[$i]) -ForegroundColor $colori[$i] }
        Firma 81
    } else {
        Write-Host ""
        Write-Host "   \  /   " -ForegroundColor White
        Write-Host "  ██████   SENTINELLA" -ForegroundColor Cyan
        Write-Host "    vv    " -ForegroundColor DarkYellow
        Firma 21
    }
    Write-Host ""
    Write-Host "  " -NoNewline
    Write-Host "[ " -NoNewline -ForegroundColor DarkGray
    Write-Host "sicurezza e salute del tuo PC" -NoNewline -ForegroundColor White
    Write-Host " ]" -NoNewline -ForegroundColor DarkGray
    Write-Host "  v$VERSIONE" -ForegroundColor DarkCyan
    Write-Host ("  " + ("=" * ([Math]::Min(80, (Larghezza) - 4)))) -ForegroundColor DarkGray
}

if (-not $silenzioso) {
    # Il .bat imposta la finestra a 45 righe; senza allargare anche la
    # "memoria" della finestra, le righe oltre la 45esima verrebbero
    # cancellate e la Parte A sparirebbe prima di poterci scorrere sopra.
    try {
        $rawui = $Host.UI.RawUI
        $buffer = $rawui.BufferSize
        if ($buffer.Height -lt 3000) { $buffer.Height = 3000; $rawui.BufferSize = $buffer }
    } catch { }
}

if (-not $Modo) {
    Clear-Host
    Insegna
    Write-Host ""
    Write-Host "   utente    : " -NoNewline -ForegroundColor DarkGray; Write-Host "$env:USERNAME@$env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "   data      : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-Date -Format 'dd/MM/yyyy HH:mm') -ForegroundColor Gray
    Write-Host "   modo      : " -NoNewline -ForegroundColor DarkGray; Write-Host "sola lettura - non cancella e non modifica nulla" -ForegroundColor Gray
    Write-Host ""
    Write-Host "   Scegli il tipo di scansione:" -ForegroundColor White
    Write-Host ""
    Write-Host "     [1]  LAMPO" -ForegroundColor Cyan
    Write-Host "          meno di un minuto, nessuna scansione antivirus." -ForegroundColor DarkGray
    Write-Host "          I segnali piu' gravi: esclusioni antivirus, avvio" -ForegroundColor DarkGray
    Write-Host "          automatico, attivita' pianificate, rete, account," -ForegroundColor DarkGray
    Write-Host "          tracce da infostealer e cosa e' cambiato dall'ultima" -ForegroundColor DarkGray
    Write-Host "          volta. Il controllo da fare ogni volta che vuoi." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "     [2]  RAPIDA" -ForegroundColor Green
    Write-Host "          circa 5 minuti." -ForegroundColor DarkGray
    Write-Host "          Tutti i controlli. L'antivirus esamina memoria," -ForegroundColor DarkGray
    Write-Host "          punti di avvio e i file a rischio aggiunti di recente" -ForegroundColor DarkGray
    Write-Host "          su TUTTI i dischi." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "     [3]  COMPLETA" -ForegroundColor Yellow
    Write-Host "          da 30 minuti a qualche ora." -ForegroundColor DarkGray
    Write-Host "          Come la rapida, ma l'antivirus apre OGNI file di" -ForegroundColor DarkGray
    Write-Host "          TUTTI i dischi. In piu': verifica dei file di sistema" -ForegroundColor DarkGray
    Write-Host "          e storico errori esteso a 30 giorni." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "     [0]  Esci" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "   Tutte controllano ogni disco: cambia solo quanto a fondo." -ForegroundColor Gray
    Write-Host ""
    do { $scelta = Read-Host "   Scrivi 1, 2, 3 o 0 e premi INVIO" } while ($scelta -notin @('0', '1', '2', '3'))
    if ($scelta -eq '0') { exit 0 }
    $Modo = @{ '1' = 'Lampo'; '2' = 'Rapida'; '3' = 'Completa' }[$scelta]
}
$lampo    = ($Modo -eq 'Lampo')
$completa = ($Modo -eq 'Completa')
$tipo     = $Modo.ToUpper()
$giorniLog = 7
if ($completa) { $giorniLog = 30 }
$da = (Get-Date).AddDays(-$giorniLog)

if (-not $silenzioso) {
    Clear-Host
    Write-Host ""
    Write-Host "  SENTINELLA $VERSIONE  -  scansione $tipo" -ForegroundColor White
    Write-Host "  Avviata il $(Get-Date -Format 'dd/MM/yyyy') alle $(Get-Date -Format 'HH:mm')" -ForegroundColor DarkGray
}
Riga "SENTINELLA $VERSIONE - scansione $tipo - $(Get-Date -Format 'dd/MM/yyyy HH:mm')"

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $silenzioso) {
    Write-Host ""
    Write-Host "  ATTENZIONE: non stai eseguendo come amministratore." -ForegroundColor Yellow
    Write-Host "  Alcuni controlli risulteranno NON VERIFICATI." -ForegroundColor Yellow
    Write-Host "  Per un esame completo chiudi e avvia SENTINELLA.bat" -ForegroundColor Yellow
}

# Dati letti una volta e usati da piu' controlli.
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$installato = (Get-Date).AddYears(-1)
if ($os -and $os.InstallDate) { $installato = $os.InstallDate }
$dischi = @(DischiFissi)
$lettere = ($dischi | ForEach-Object { "$($_.DriveLetter):" }) -join '  '
Scrivi "" Gray
Scrivi "  Dischi rilevati: $lettere" Gray
Riga "Dischi rilevati: $lettere"

# ============================================================ CONTROLLI
# L'elenco dei controlli e' un dato, non codice sparso: il numero totale
# si calcola da qui (nella v2 era scritto a mano, e andava tenuto in
# pari a ogni controllo aggiunto) e ogni voce dice in quali modalita' gira.
$sA = "PARTE A  -  SICUREZZA"
$sB = "PARTE B  -  TRACCE DA INFOSTEALER"
$sC = "PARTE C  -  SALUTE DEL PC"
$sD = "PARTE D  -  ESAME ANTIVIRUS SU TUTTI I DISCHI"
$sE = "PARTE E  -  CONFRONTO CON L'ULTIMA SCANSIONE"
$controlli = @(
    @{ S = $sA; T = "Integrita' di Sentinella";                           F = { C_IntegritaSentinella }; Lampo = $true }
    @{ S = $sA; T = "Sistema";                                             F = { C_Sistema };             Lampo = $true }
    @{ S = $sA; T = "Antivirus";                                           F = { C_Antivirus };           Lampo = $true }
    @{ S = $sA; T = "Esclusioni antivirus  (trucco classico dei malware)"; F = { C_Esclusioni };          Lampo = $true }
    @{ S = $sA; T = "Storico minacce";                                     F = { C_StoricoMinacce };      Lampo = $true }
    @{ S = $sA; T = "Firewall";                                            F = { C_Firewall };            Lampo = $true }
    @{ S = $sA; T = "Programmi in avvio automatico";                       F = { C_Avvio };               Lampo = $true }
    @{ S = $sA; T = "Nascondigli di avvio avanzati";                       F = { C_NascondigliAvanzati }; Lampo = $true }
    @{ S = $sA; T = "Attivita' pianificate";                               F = { C_Attivita };            Lampo = $true }
    @{ S = $sA; T = "Processi in esecuzione";                              F = { C_Processi };            Lampo = $false }
    @{ S = $sA; T = "Servizi e persistenza avanzata";                      F = { C_Servizi };             Lampo = $true }
    @{ S = $sA; T = "Estensioni del browser";                              F = { C_Estensioni };          Lampo = $false }
    @{ S = $sA; T = "Rete: file hosts, proxy, DNS";                        F = { C_Rete };                Lampo = $true }
    @{ S = $sA; T = "Connessioni di rete e account";                       F = { C_Connessioni };         Lampo = $true }
    @{ S = $sB; T = "Comandi incollati  (trucco ClickFix)";                F = { C_ComandiIncollati };    Lampo = $true }
    @{ S = $sB; T = "File scaricati di recente (14 giorni)";               F = { C_FileScaricati };       Lampo = $false }
    @{ S = $sB; T = "Programmi avviati di recente da cartelle a rischio";  F = { C_EseguitiDiRecente };   Lampo = $true }
    @{ S = $sB; T = "Discord: file di avvio manomesso";                    F = { C_Discord };             Lampo = $true }
    @{ S = $sC; T = "Dischi: spazio libero";                               F = { C_Spazio };              Lampo = $false }
    @{ S = $sC; T = "Dischi: stato fisico (SMART)";                        F = { C_Smart };               Lampo = $false }
    @{ S = $sC; T = "Memoria";                                             F = { C_Memoria };             Lampo = $false }
    @{ S = $sC; T = "Errori critici di sistema (ultimi $giorniLog giorni)"; F = { C_ErroriSistema };      Lampo = $false }
    @{ S = $sC; T = "Errori hardware e spegnimenti (ultimi 90 giorni)";    F = { C_ErroriHardware };      Lampo = $false }
    @{ S = $sC; T = "Crash e file di dump";                                F = { C_Crash };               Lampo = $false }
    @{ S = $sC; T = "Driver e periferiche";                                F = { C_Periferiche };         Lampo = $false }
    @{ S = $sC; T = "Aggiornamenti e riavvio in sospeso";                  F = { C_Aggiornamenti };       Lampo = $false }
    @{ S = $sC; T = "Programmi installati di recente (30 giorni)";         F = { C_ProgrammiRecenti };    Lampo = $false }
    @{ S = $sC; T = "Integrita' dei file di sistema";                      F = { C_Integrita };           Lampo = $false }
    @{ S = $sD; T = "Esame antivirus";                                     F = { C_EsameAntivirus };      Lampo = $false }
    @{ S = $sE; T = "Novita' dall'ultima scansione";                       F = { C_Confronto };           Lampo = $true }
)
$daEseguire = @($controlli | Where-Object { $_.Lampo -or -not $lampo })
$TOTPASSI = $daEseguire.Count
$sezPrec = ''
foreach ($c in $daEseguire) {
    if ($c.S -ne $sezPrec) { Sezione $c.S; $sezPrec = $c.S }
    EseguiControllo $c.T $c.F
}

# =============================================================== REPORT
$durata = [math]::Round(((Get-Date) - $inizio).TotalMinutes, 1)
Sezione "REPORT FINALE  -  scansione $tipo"
$v = Verdetto
$dati = DatiJson $v
$fileStorico = SalvaStorico $dati

if ($silenzioso) {
    if ($fileStorico) { Write-Output "Sentinella $VERSIONE - $tipo - $($v.Titolo): $($v.Sotto) - report: $fileStorico" }
    exit $v.Codice
}

ReportSchermo $v
if ($fileStorico) { Write-Host "   Copia del report per lo storico: $fileStorico" -ForegroundColor DarkGray }

# --- salvataggio su richiesta ---------------------------------------
Write-Host ("   " + ("-" * 68)) -ForegroundColor DarkGray
Write-Host "   Vuoi salvare il report sul Desktop?" -ForegroundColor White
Write-Host "     [T] testo   [H] pagina web   [J] JSON   [E] tutti e tre   [N] no" -ForegroundColor DarkGray
$risposta = Read-Host "   Scegli (puoi combinarle, es. TH)"
$vuoleTxt  = $risposta -match '[TtEe]'
$vuoleHtml = $risposta -match '[HhEe]'
$vuoleJson = $risposta -match '[JjEe]'
Write-Host ""
if ($vuoleTxt -or $vuoleHtml -or $vuoleJson) { SalvaReport $v $vuoleTxt $vuoleHtml $vuoleJson $dati }
else { Write-Host "   Nessun file creato sul Desktop: il report resta qui a schermo." -ForegroundColor DarkGray }

if (-not $lampo) { OffriScansioneOffline }

Write-Host ""
Write-Host "   " -NoNewline
Write-Host "Sentinella v$VERSIONE" -NoNewline -ForegroundColor DarkCyan
Write-Host "  ~  " -NoNewline -ForegroundColor DarkGray
Write-Host "by " -NoNewline -ForegroundColor DarkGray
Write-Host "lozy" -ForegroundColor Cyan
Write-Host ""
Write-Host "   Premi INVIO per chiudere..." -ForegroundColor DarkGray
Read-Host | Out-Null
exit $v.Codice

# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCb76UuMbxV7VeQ
# uYuGPKe3Fqfxp+5YKQC4KR6jG6nsg6CCBCowggQmMIICjqADAgECAhBsFNOb1/0T
# iEmLgLsWwl8pMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFNlbnRpbmVsbGEg
# LSBmaXJtYSBjb2RpY2UgKGxvenkpMB4XDTI2MTEyNDA5MTQ1NVoXDTMxMTEyNDA5
# MjQ1NVowKzEpMCcGA1UEAwwgU2VudGluZWxsYSAtIGZpcm1hIGNvZGljZSAobG96
# eSkwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC6qg0jNOiPdZyNKY0U
# GQK6Phvr9OokrbArSlmCe2xlKsw/XCPaOTn4AdzFVTjqyPs/Nzc/v7c0G4vHk2N4
# BcMrNAbsLhJKUH9MKLcxhXfxv5OsCDn0e7/opw/PNKuvwGdU5hFNxZF58hUZWb8u
# 5nFSiEYTno20mhjbOALNzmSq5rMme1oWqcPJYhNWaYMFHBcIP5LtHqUaKk9l+y/Z
# ZCJfmMugalMs4vB90/nZcP+nY89yOP9ubhfW4jPvwKGLxcL1E2HbMwBL7mfUAXNi
# tHem1pUAIlUnCmHF3IUNkfqbc5gppzaMXUrjGwc0z3hAZMe7jBf2cQoQjBkZmw92
# 61Qw1xvcQbl2Uf+53J/bjnaL5mTSC23z+B41kHRqKCgaEYx++S2ETnHP/iK30wHp
# QBlVeji17o1Q+rYhKurSCo/rpYUNYuWjveaIEsE1CC+HkAYwOj1Ow6yFqwv3IM6c
# VftUHr4ohi8qH1mIn0sFyFGpNhsdQQx3v+vHwD+C5qbrYMECAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSgWVtU
# sJIm3AmrnSf7a7fTW+AcDDANBgkqhkiG9w0BAQsFAAOCAYEAgPMQAXl/uTNDe79T
# cjO0KimKaiet/wRlDr4D3cU6NTOjiqtrEZoJCFvB3j2HWsp/2zeQ1s/LVDCypUar
# rRfIqG6Jfwv7C8eYFA0tiHXFcTF+CZudfppJEsjixHfKkD87uAtSmHuWpK2RfeGL
# yxc2i9uT+7eQivgmT7nVD2BPAIgr6RurNL4FoNaXLSt/39T+QbC5ciPF7UAKkEV0
# vV+PQrhWVinRiKRtqYL1MufYzRTMMIj0V4pdNWHKoptf1gRGP/5HzWPRGNI0kDSc
# GgrIEBwgKNovp5XL47/ltqbfIvXgtRbhp9yaNkBWs1nVJsUKHYSoZ/29P8z7YF8s
# PdBfn5jZ4gZJEkEXNUCYHZ2h0Q7cAPMGXtYoqxVPeXonKvc4TNJ5jaKmoaJv8nAq
# eLzl7+2+ZbQuXwBk0vVFltBGCKBFEvyOEleNo68ORavNHRfJK7iLqVPjGhsw5w56
# NCu/2sE+fzB1VsYt40bURsvodSmFo3zrf26iKFAFvQkUJCyDMYICcTCCAm0CAQEw
# PzArMSkwJwYDVQQDDCBTZW50aW5lbGxhIC0gZmlybWEgY29kaWNlIChsb3p5KQIQ
# bBTTm9f9E4hJi4C7FsJfKTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEM
# MQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBjFZ8qoqIdnD3h
# xVdDYyY2Zs04230WwOaa6y/YipnIbTANBgkqhkiG9w0BAQEFAASCAYBzL8ZfO6sx
# fGGDHziEy+L4uVCNYQz9w5zAMfBP5CqF6Svz+uH0qj4oIiLgQkIgLb7yjDythjvz
# 7fOYON9S4rYi5vAavC1r1tbIy50BtxmrN9BN9B8jY2TSnVUVvfgNam74T6DxAECZ
# wGeAX2ggoIMHJrTvFtfqcJLbXlYM+k/D8EZEkaQ+DvTa3pNf6Ygz2X0k7Ly4Xm1+
# MUv5Ldy9ch9yMyo+6pHgkX48Wc24mGpDAzQFGQkn+Ca9O+5OcM0f0Vn5/o88PZ8F
# 6A5UEt4L719aJcR6pSk4qggpfGffHB1oI2zMhC6NGvBzCA6G+/tBb+P9I/CNFbfM
# XfTEuAr0rj+J0hMQUQuLp15eH6CAhRML9uzT12IukJeDlaaGpm2yITqhWWTuOozg
# 6WWRgAwHyFGq99+/QWHgBv76KUJJinn6Smk5tX9bH5Y6ivRoJ4RnBZ4WyMqYQOKT
# hhLIvGn03OgbulG/YyKwKAAERvzk/ddriRVs59MZtUJB7+kTg401iko=
# SIG # End signature block
