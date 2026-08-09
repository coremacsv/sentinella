# =====================================================================
#
#   SENTINELLA  -  sicurezza e salute del tuo PC
#   Versione 2.0  -  by lozy
#
#   Uno strumento unico che risponde a due domande:
#     "Il mio PC e' infetto?"  e  "Il mio PC sta bene?"
#
#   SOLA LETTURA: non cancella, non modifica, non installa nulla.
#   Le uniche azioni attive sono la scansione di Windows Defender e
#   'sfc /verifyonly', entrambi strumenti Microsoft che si limitano
#   a verificare.
#
#   Nato dopo una vera infezione da infostealer, in cui l'antivirus
#   non aveva rilevato nulla e il file infetto era sopravvissuto alla
#   formattazione perche' si trovava su un secondo disco.
#
# =====================================================================

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$VERSIONE = '2.0'

$allarmi  = New-Object System.Collections.ArrayList   # sicurezza, grave
$sospetti = New-Object System.Collections.ArrayList   # sicurezza, da guardare
$problemi = New-Object System.Collections.ArrayList   # salute, grave
$avvisi   = New-Object System.Collections.ArrayList   # salute, da guardare
$diario   = New-Object System.Collections.ArrayList   # tutto, per il report
$inizio   = Get-Date
$passo    = 0
$TOTPASSI = 24

function Riga($t) { [void]$diario.Add($t) }
# Per ogni controllo teniamo l'esito peggiore incontrato, cosi' alla fine
# si puo' mostrare il quadro completo invece delle sole cose andate storte.
$esiti = New-Object System.Collections.Specialized.OrderedDictionary
$sezioneDi = @{}
$checkCorrente = ''
$sezioneCorrente = ''
function Segna([int]$livello) {
    if (-not $script:checkCorrente) { return }
    if ($script:esiti[$script:checkCorrente] -lt $livello) { $script:esiti[$script:checkCorrente] = $livello }
}
function Titolo($t) {
    $script:passo++
    $script:checkCorrente = $t
    $script:esiti[$t] = 0
    $script:sezioneDi[$t] = $script:sezioneCorrente
    Write-Host ""
    Write-Host ("-" * 74) -ForegroundColor DarkGray
    Write-Host ("  [{0}/{1}]  {2}" -f $script:passo, $TOTPASSI, $t) -ForegroundColor Cyan
    Write-Host ("-" * 74) -ForegroundColor DarkGray
    Riga ""
    Riga "--- $t ---"
}
function Sezione($t) {
    $script:sezioneCorrente = $t
    Write-Host ""
    Write-Host ("=" * 74) -ForegroundColor White
    Write-Host "   $t" -ForegroundColor White
    Write-Host ("=" * 74) -ForegroundColor White
    Riga ""
    Riga "=== $t ==="
}
function Ok($m)         { Write-Host "  [ OK ] $m" -ForegroundColor Green;  Riga "  [OK] $m" }
function Nota($m)       { Write-Host "  [ .. ] $m" -ForegroundColor Gray;   Riga "  [..] $m" }
function Attenzione($m) { Write-Host "  [ !! ] $m" -ForegroundColor Yellow; Riga "  [!!] $m"; [void]$sospetti.Add($m); Segna 1 }
function Allarme($m)    { Write-Host "  [ XX ] $m" -ForegroundColor Red;    Riga "  [XX] $m"; [void]$allarmi.Add($m);  Segna 2 }
function Avviso($m)     { Write-Host "  [ !! ] $m" -ForegroundColor Yellow; Riga "  [!!] $m"; [void]$avvisi.Add($m);   Segna 1 }
function Problema($m)   { Write-Host "  [ XX ] $m" -ForegroundColor Red;    Riga "  [XX] $m"; [void]$problemi.Add($m); Segna 2 }
function NonDisponibile($m) {
    Write-Host "  [ -- ] $m" -ForegroundColor DarkGray; Riga "  [--] $m"
    # 3 = "non applicabile su questo PC". Non e' un problema, ma nemmeno
    # un via libera: va distinto da un controllo passato davvero.
    if ($script:checkCorrente -and $script:esiti[$script:checkCorrente] -eq 0) {
        $script:esiti[$script:checkCorrente] = 3
    }
}
function Esiste($cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# Una scansione antivirus puo' durare minuti senza stampare una riga, e
# una finestra immobile sembra bloccata. Il lavoro viene quindi avviato in
# parallelo e nel frattempo si mostra un indicatore che gira, con il tempo
# trascorso: cosi' si vede sempre che il programma sta lavorando.
function Attendi($lavoro, $etichetta) {
    $rot = @('|', '/', '-', '\')
    $i = 0
    $t0 = Get-Date
    while ($lavoro.State -eq 'Running') {
        $s = [int]((Get-Date) - $t0).TotalSeconds
        $t = "      [{0}]  {1}  in esecuzione...  {2:00}:{3:00}" -f $rot[$i % 4], $etichetta, [int]($s / 60), ($s % 60)
        Write-Host ("`r" + $t.PadRight(76)) -NoNewline -ForegroundColor DarkCyan
        Start-Sleep -Milliseconds 200
        $i++
    }
    $null = Receive-Job $lavoro -ErrorAction SilentlyContinue
    Remove-Job $lavoro -Force -ErrorAction SilentlyContinue
    $tot = [int]((Get-Date) - $t0).TotalSeconds
    Write-Host ("`r" + (" " * 76)) -NoNewline
    Write-Host ("`r      [v]  {0}  -  completata in {1} secondi" -f $etichetta, $tot) -ForegroundColor DarkGray
}

# Stessa idea per un programma esterno (usato da sfc, che non e' un job).
function AttendiProcesso($proc, $etichetta) {
    $rot = @('|', '/', '-', '\')
    $i = 0
    $t0 = Get-Date
    while (-not $proc.HasExited) {
        $s = [int]((Get-Date) - $t0).TotalSeconds
        $t = "      [{0}]  {1}  in esecuzione...  {2:00}:{3:00}" -f $rot[$i % 4], $etichetta, [int]($s / 60), ($s % 60)
        Write-Host ("`r" + $t.PadRight(76)) -NoNewline -ForegroundColor DarkCyan
        Start-Sleep -Milliseconds 200
        $i++
    }
    $tot = [int]((Get-Date) - $t0).TotalSeconds
    Write-Host ("`r" + (" " * 76)) -NoNewline
    Write-Host ("`r      [v]  {0}  -  completata in {1} secondi" -f $etichetta, $tot) -ForegroundColor DarkGray
}

# Cartelle da cui un programma legittimo di solito NON parte.
$percorsiSospetti = @(
    "$env:LOCALAPPDATA\Temp", "$env:TEMP", "$env:APPDATA",
    "$([Environment]::GetFolderPath('UserProfile'))\Downloads",
    "$env:PUBLIC", "$env:ProgramData"
)
function EsuPercorsoSospetto($p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $false }
    foreach ($s in $percorsiSospetti) { if ($p -like "$s*") { return $true } }
    return $false
}
# I malware comuni non sono firmati digitalmente. Senza questo controllo
# lo strumento accusa Windows Defender stesso, che vive sotto ProgramData.
function FirmaValida($p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $false }
    if (-not (Test-Path -LiteralPath $p)) { return $false }
    return ((Get-AuthenticodeSignature -LiteralPath $p).Status -eq 'Valid')
}
# L'impronta SHA256 permette di verificare un file sospetto su VirusTotal
# senza caricarlo: si incolla il codice nella casella di ricerca.
function Impronta($p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return '' }
    if (-not (Test-Path -LiteralPath $p)) { return '' }
    try { return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } catch { return '' }
}
# Un indirizzo numerico non dice niente a nessuno: qui si prova a
# risalire al nome del sito, con un tetto di tempo per non bloccare
# tutto quando l'indirizzo non risponde.
$cacheDns = @{}
function NomeHost($ip) {
    if ($script:cacheDns.ContainsKey($ip)) { return $script:cacheDns[$ip] }
    $nome = $ip
    try {
        $t = [System.Net.Dns]::GetHostEntryAsync($ip)
        if ($t.Wait(700) -and $t.Result -and $t.Result.HostName) { $nome = $t.Result.HostName }
    } catch { }
    $script:cacheDns[$ip] = $nome
    return $nome
}
function NomeFirmatario($p) {
    $f = Get-AuthenticodeSignature -LiteralPath $p
    if ($f -and $f.SignerCertificate) {
        $s = $f.SignerCertificate.Subject
        # Il nome puo' essere tra virgolette e contenere virgole
        # (es. CN="Corsair Memory, Inc.", O=...).
        $m = [regex]::Match($s, '^CN="([^"]+)"')
        if ($m.Success) { return $m.Groups[1].Value }
        $m = [regex]::Match($s, '^CN=([^,]+)')
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
    }
    return "sconosciuto"
}
function DischiFissi {
    $d = Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystem -and $_.DriveType -eq 'Fixed' }
    if (-not $d) {
        # Ripiego per sistemi in cui Get-Volume non espone DriveType
        $d = Get-PSDrive -PSProvider FileSystem | Where-Object { $null -ne $_.Free }
    }
    return $d
}

# =============================================================== MENU
Clear-Host
Write-Host ""
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
    # Gradiente monotono chiaro->scuro dall'alto in basso. Prima andava
    # scuro-scuro-CHIARO-CHIARO-scuro-scuro: il salto di luminosita' a
    # meta' rendeva la scritta "a bande" invece che sfumata.
    $colori = @('Cyan','Cyan','DarkCyan','DarkCyan','Blue','DarkBlue')
    # La vespa: SOLO caratteri del blocco CP437 (mattoni/mezzi mattoni),
    # niente diagonali (╲╱◥◤▼). Quei caratteri non fanno parte del set
    # box-drawing/block classico: il terminale li disegna con un font
    # sostitutivo diverso da quello usato per il resto della riga, ed
    # e' quello che produceva la macchia sfocata al posto della vespa.
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

# Senza questo i caratteri a blocchi escono come punti interrogativi.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

Insegna
Write-Host ""
Write-Host "   utente    : " -NoNewline -ForegroundColor DarkGray; Write-Host "$env:USERNAME@$env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "   data      : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-Date -Format 'dd/MM/yyyy HH:mm') -ForegroundColor Gray
Write-Host "   controlli : " -NoNewline -ForegroundColor DarkGray; Write-Host "$TOTPASSI  (sicurezza + salute)" -ForegroundColor Gray
Write-Host "   modo      : " -NoNewline -ForegroundColor DarkGray; Write-Host "sola lettura - non cancella e non modifica nulla" -ForegroundColor Gray
Write-Host ""
Write-Host "   Scegli il tipo di scansione:" -ForegroundColor White
Write-Host ""
Write-Host "     [1]  RAPIDA" -ForegroundColor Green
Write-Host "          circa 5 minuti." -ForegroundColor DarkGray
Write-Host "          Tutti i $TOTPASSI controlli. L'antivirus esamina memoria," -ForegroundColor DarkGray
Write-Host "          punti di avvio e i file a rischio aggiunti di recente" -ForegroundColor DarkGray
Write-Host "          su TUTTI i dischi." -ForegroundColor DarkGray
Write-Host ""
Write-Host "     [2]  COMPLETA" -ForegroundColor Yellow
Write-Host "          da 30 minuti a qualche ora." -ForegroundColor DarkGray
Write-Host "          Come la rapida, ma l'antivirus apre OGNI file di" -ForegroundColor DarkGray
Write-Host "          TUTTI i dischi. In piu': verifica dei file di sistema" -ForegroundColor DarkGray
Write-Host "          e storico errori esteso a 30 giorni." -ForegroundColor DarkGray
Write-Host ""
Write-Host "     [0]  Esci" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   Entrambe controllano tutti i dischi: cambia quanto a fondo." -ForegroundColor Gray
Write-Host ""
$scelta = Read-Host "   Scrivi 1, 2 o 0 e premi INVIO"
if ($scelta -eq '0') { exit }
$completa = ($scelta -eq '2')
if ($completa) { $tipo = "COMPLETA"; $giorniLog = 30 } else { $tipo = "RAPIDA"; $giorniLog = 7 }

Clear-Host
Write-Host ""
Write-Host "  SENTINELLA $VERSIONE  -  scansione $tipo" -ForegroundColor White
Write-Host "  Avviata il $(Get-Date -Format 'dd/MM/yyyy') alle $(Get-Date -Format 'HH:mm')" -ForegroundColor DarkGray
Riga "SENTINELLA $VERSIONE - scansione $tipo - $(Get-Date -Format 'dd/MM/yyyy HH:mm')"

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host ""
    Write-Host "  ATTENZIONE: non stai eseguendo come amministratore." -ForegroundColor Yellow
    Write-Host "  Alcuni controlli saranno parziali o non disponibili." -ForegroundColor Yellow
    Write-Host "  Per un esame completo chiudi e avvia SENTINELLA.bat" -ForegroundColor Yellow
}

$dischi = DischiFissi
$lettere = ($dischi | ForEach-Object { "$($_.DriveLetter):" }) -join '  '
Write-Host ""
Write-Host "  Dischi rilevati: $lettere" -ForegroundColor Gray
Riga "Dischi rilevati: $lettere"

# =====================================================================
Sezione "PARTE A  -  SICUREZZA"
# =====================================================================

Titolo "Sistema"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$installato = $os.InstallDate
$giorniOS = [math]::Round(((Get-Date) - $installato).TotalDays, 1)
Nota "Windows  : $($os.Caption) build $($os.BuildNumber)"
Nota "Computer : $($cs.Manufacturer) $($cs.Model)"
Nota "Installato: $($installato.ToString('dd/MM/yyyy HH:mm'))  ($giorniOS giorni fa)"
Nota "Acceso da : $([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours,1)) ore"
Ok "Informazioni di sistema raccolte"

Titolo "Antivirus"
if (Esiste 'Get-MpComputerStatus') {
    $mp = Get-MpComputerStatus
    if ($mp) {
        if ($mp.RealTimeProtectionEnabled) { Ok "Protezione in tempo reale ATTIVA" }
        else { Allarme "Protezione in tempo reale DISATTIVATA (e' la prima cosa che un malware spegne)" }
        if ($mp.AntivirusEnabled) { Ok "Antivirus attivo" } else { Allarme "Antivirus NON attivo" }
        $etaDef = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays
        if ($etaDef -le 3) { Ok "Definizioni aggiornate ($([math]::Round($etaDef,1)) giorni)" }
        elseif ($etaDef -le 14) { Attenzione "Definizioni vecchie di $([math]::Round($etaDef,1)) giorni" }
        else { Allarme "Definizioni vecchie di $([math]::Round($etaDef,1)) giorni: l'antivirus e' quasi cieco" }
        if ($mp.IsTamperProtected) { Ok "Protezione da manomissione attiva" }
        else { Attenzione "Protezione da manomissione disattivata" }
    } else { NonDisponibile "Stato di Defender non leggibile" }
} else {
    NonDisponibile "Windows Defender non presente (probabile antivirus di terze parti)"
    Attenzione "Verifica a mano che il tuo antivirus sia attivo e aggiornato"
}

Titolo "Esclusioni antivirus  (trucco classico dei malware)"
if (-not (Esiste 'Get-MpPreference')) { NonDisponibile "Defender non presente, controllo non applicabile" }
elseif (-not $admin) { Attenzione "Non leggibili senza permessi di amministratore" }
else {
    $pref = Get-MpPreference
    $esc = @()
    foreach ($v in $pref.ExclusionPath)      { if ($v -and $v -notlike 'N/A*') { $esc += "cartella: $v" } }
    foreach ($v in $pref.ExclusionProcess)   { if ($v -and $v -notlike 'N/A*') { $esc += "processo: $v" } }
    foreach ($v in $pref.ExclusionExtension) { if ($v -and $v -notlike 'N/A*') { $esc += "estensione: $v" } }
    if ($esc.Count -eq 0) { Ok "Nessuna esclusione impostata" }
    else {
        foreach ($e in $esc) { Allarme "Esclusione -> $e" }
        Nota "Un'esclusione dice all'antivirus di NON controllare quel punto."
        Nota "Se non l'hai messa tu, e' un segnale molto serio."
    }
}

Titolo "Storico minacce"
if (-not (Esiste 'Get-MpThreatDetection')) { NonDisponibile "Non applicabile senza Defender" }
else {
    $minacce = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending
    if (-not $minacce) { Ok "Nessuna minaccia mai rilevata su questo sistema" }
    else {
        Nota "$($minacce.Count) rilevamenti in archivio. Ultimi 10:"
        foreach ($m in ($minacce | Select-Object -First 10)) {
            $nome = (Get-MpThreat | Where-Object { $_.ThreatID -eq $m.ThreatID } | Select-Object -First 1).ThreatName
            if (-not $nome) { $nome = "ID $($m.ThreatID)" }
            $q = $m.InitialDetectionTime.ToString('dd/MM/yyyy HH:mm')
            if ($m.ThreatStatusID -in 2,3) { Attenzione "$q - $nome - NON risolta" }
            else { Nota "   $q - $nome - risolta o in quarantena" }
        }
    }
}

Titolo "Firewall"
if (-not (Esiste 'Get-NetFirewallProfile')) { NonDisponibile "Controllo non disponibile su questo sistema" }
else {
    foreach ($p in (Get-NetFirewallProfile)) {
        if ($p.Enabled) { Ok "Profilo $($p.Name): attivo" }
        else { Attenzione "Profilo $($p.Name): DISATTIVATO" }
    }
}

Titolo "Programmi in avvio automatico"
$chiavi = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$nAvvio = 0
foreach ($k in $chiavi) {
    $item = Get-ItemProperty -Path $k
    if (-not $item) { continue }
    foreach ($p in $item.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $nAvvio++
        $val = [string]$p.Value
        if (EsuPercorsoSospetto $val)  { Allarme "Avvio da cartella anomala: $($p.Name) -> $val" }
        elseif ($val -match '\.(vbs|js|jse|bat|cmd|ps1|scr|hta)(\"|\s|$)') { Allarme "Avvio tramite script: $($p.Name) -> $val" }
        else { Nota "   $($p.Name)" }
    }
}
foreach ($cart in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
    foreach ($x in (Get-ChildItem -LiteralPath $cart -File)) {
        $nAvvio++
        Attenzione "File nella cartella Esecuzione automatica: $($x.FullName)"
    }
}
Nota "Totale voci in avvio: $nAvvio"
if ($nAvvio -gt 25) { Avviso "Molti programmi in avvio ($nAvvio): il computer parte piu' lento" }

Titolo "Nascondigli di avvio avanzati"
# Le chiavi qui sotto sono poco note e quasi sempre vuote o con un valore
# fisso: sono il posto dove si mette chi non vuole comparire nell'elenco
# ovvio dei programmi in avvio.
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl) {
    if ($wl.Shell -and $wl.Shell.Trim() -ne 'explorer.exe') {
        Allarme "Winlogon Shell modificata: '$($wl.Shell)' invece di 'explorer.exe'"
    } else { Ok "Winlogon Shell regolare (explorer.exe)" }
    $ui = "$($wl.Userinit)".Trim().TrimEnd(',')
    if ($ui -and $ui -notmatch '(?i)^[A-Z]:\\Windows\\system32\\userinit\.exe$') {
        Allarme "Winlogon Userinit modificato: '$ui'"
    } else { Ok "Winlogon Userinit regolare" }
}
$ai = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
if ($ai -and $ai.AppInit_DLLs -and $ai.AppInit_DLLs.Trim()) {
    Allarme "AppInit_DLLs non vuoto: '$($ai.AppInit_DLLs)' - carica una libreria in ogni programma"
} else { Ok "AppInit_DLLs vuoto (nessuna libreria iniettata ovunque)" }

# IFEO: nato per agganciare un debugger a un programma, viene usato per
# far partire altro al posto suo (o per impedire l'avvio degli antivirus).
$ifeo = 0
foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue)) {
    $d = (Get-ItemProperty $k.PSPath).Debugger
    if ($d) { $ifeo++; Allarme "Dirottamento IFEO su '$($k.PSChildName)' -> $d" }
}
if ($ifeo -eq 0) { Ok "Nessun dirottamento IFEO" }

$bho = 0
foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' -ErrorAction SilentlyContinue)) {
    $bho++
    Nota "   componente aggiuntivo di sistema: $($k.PSChildName)"
}
if ($bho -eq 0) { Ok "Nessun componente aggiuntivo agganciato a Explorer" }

Titolo "Attivita' pianificate"
$b = 0
foreach ($t in (Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' })) {
    foreach ($a in $t.Actions) {
        $ex = $a.Execute
        if (-not $ex) { continue }
        $ex = $ex.Trim('"')
        if ((EsuPercorsoSospetto $ex) -or ($ex -match '\.(vbs|js|jse|hta|scr)$')) {
            if (FirmaValida $ex) { Nota "   $($t.TaskName) -> firmato da $(NomeFirmatario $ex)" }
            else { $b++; Allarme "Attivita' '$($t.TaskName)' esegue un file NON firmato: $ex  [SHA256 $(Impronta $ex)]" }
        }
    }
}
if ($b -eq 0) { Ok "Nessuna attivita' pianificata sospetta" }

Titolo "Processi in esecuzione"
$b = 0
foreach ($p in (Get-Process | Where-Object { $_.Path } | Sort-Object ProcessName -Unique)) {
    if (EsuPercorsoSospetto $p.Path) {
        if (FirmaValida $p.Path) { Nota "   $($p.ProcessName) - cartella utente ma firmato da $(NomeFirmatario $p.Path)" }
        else { $b++; Attenzione "$($p.ProcessName) NON firmato, in esecuzione da $($p.Path)  [SHA256 $(Impronta $p.Path)]" }
    }
}
if ($b -eq 0) { Ok "Nessun processo non firmato da cartelle anomale" }

Titolo "Servizi e persistenza avanzata"
$b = 0
foreach ($s in (Get-CimInstance Win32_Service | Where-Object { $_.PathName })) {
    $pn = $s.PathName -replace '^"([^"]+)".*$', '$1'
    if (EsuPercorsoSospetto $pn) {
        if (FirmaValida $pn) { Nota "   $($s.Name) -> firmato da $(NomeFirmatario $pn)" }
        else { $b++; Allarme "Servizio '$($s.Name)' NON firmato: $pn  [SHA256 $(Impronta $pn)]" }
    }
}
if ($b -eq 0) { Ok "Nessun servizio non firmato in cartelle utente" }
$wmiNoti = @('SCM Event Log Filter','BVTFilter')
$wmi = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Where-Object { $wmiNoti -notcontains $_.Name }
if ($wmi) { foreach ($w in $wmi) { Attenzione "Sottoscrizione WMI non standard: $($w.Name) (tecnica di persistenza avanzata)" } }
else { Ok "Nessuna persistenza WMI sospetta" }

Titolo "Estensioni del browser"
# Un'estensione malevola legge tutto quello che scrivi nel browser, password
# comprese, e non compare da nessuna parte tra i programmi installati.
$browser = @(
    @{ Nome = 'Chrome';  Base = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
    @{ Nome = 'Edge';    Base = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
    @{ Nome = 'Brave';   Base = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" },
    @{ Nome = 'Vivaldi'; Base = "$env:LOCALAPPDATA\Vivaldi\User Data" },
    @{ Nome = 'Opera';   Base = "$env:APPDATA\Opera Software\Opera Stable" }
)
$recenteEst = (Get-Date).AddDays(-45)
# Su un Windows appena installato tutto risulta "recente" e ogni estensione
# verrebbe segnalata: in quel caso conta solo cio' che e' comparso DOPO la
# configurazione iniziale del computer.
$sogliaSetup = $installato.AddDays(2)
if ($recenteEst -lt $sogliaSetup) { $recenteEst = $sogliaSetup }
$totEst = 0; $nuoveEst = 0; $trovatoBrowser = $false
foreach ($b in $browser) {
    if (-not (Test-Path -LiteralPath $b.Base)) { continue }
    $trovatoBrowser = $true
    $nb = 0
    foreach ($prof in (Get-ChildItem -LiteralPath $b.Base -Directory -ErrorAction SilentlyContinue)) {
        $dirEst = Join-Path $prof.FullName 'Extensions'
        if (-not (Test-Path -LiteralPath $dirEst)) { continue }
        foreach ($est in (Get-ChildItem -LiteralPath $dirEst -Directory -ErrorAction SilentlyContinue)) {
            $ver = Get-ChildItem -LiteralPath $est.FullName -Directory -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if (-not $ver) { continue }
            $totEst++; $nb++
            $nome = $est.Name
            $man = Join-Path $ver.FullName 'manifest.json'
            if (Test-Path -LiteralPath $man) {
                try {
                    $j = Get-Content -LiteralPath $man -Raw | ConvertFrom-Json
                    if ($j.name -and $j.name -notlike '__MSG_*') { $nome = $j.name }
                } catch { }
            }
            if ($ver.LastWriteTime -ge $recenteEst) {
                $nuoveEst++
                Attenzione "$($b.Nome): estensione aggiunta di recente - '$nome' ($($ver.LastWriteTime.ToString('dd/MM/yyyy')))"
            }
        }
    }
    if ($nb -gt 0) { Nota "   $($b.Nome): $nb estensioni installate" }
}
# Firefox tiene le estensioni in file .xpi dentro il profilo.
$ffBase = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path -LiteralPath $ffBase) {
    $trovatoBrowser = $true
    $nff = 0
    foreach ($x in (Get-ChildItem -LiteralPath $ffBase -Recurse -Filter '*.xpi' -ErrorAction SilentlyContinue)) {
        $totEst++; $nff++
        if ($x.LastWriteTime -ge $recenteEst) {
            $nuoveEst++
            Attenzione "Firefox: estensione aggiunta di recente - '$($x.BaseName)' ($($x.LastWriteTime.ToString('dd/MM/yyyy')))"
        }
    }
    if ($nff -gt 0) { Nota "   Firefox: $nff estensioni installate" }
}
if (-not $trovatoBrowser) { NonDisponibile "Nessun browser conosciuto trovato su questo utente" }
elseif ($nuoveEst -eq 0) { Ok "$totEst estensioni in totale, nessuna aggiunta negli ultimi 45 giorni" }
else { Nota "Controlla che le estensioni recenti le abbia installate tu." }

Titolo "Rete: file hosts, proxy, DNS"
$fileHosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$righeHosts = Get-Content -LiteralPath $fileHosts | Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') }
if (-not $righeHosts) { Ok "File hosts pulito (nessun sito dirottato)" }
else { foreach ($r in $righeHosts) { Allarme "Riga nel file hosts: $r" } }

$ie = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$pIE = Get-ItemProperty -Path $ie
if ($pIE.ProxyEnable -eq 1) { Allarme "PROXY ATTIVO ($($pIE.ProxyServer)): puo' leggere tutto il traffico" }
else { Ok "Nessun proxy configurato" }
if ($pIE.AutoConfigURL) { Allarme "Configurazione proxy scaricata da: $($pIE.AutoConfigURL)" }

if (Esiste 'Get-DnsClientServerAddress') {
    foreach ($d in (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses })) {
        Nota "   DNS su '$($d.InterfaceAlias)': $($d.ServerAddresses -join ', ')"
    }
    Nota "Se non riconosci un indirizzo DNS, verificalo: e' un modo per dirottare i siti."
} else { NonDisponibile "Lettura DNS non disponibile" }

Titolo "Connessioni di rete e account"
$conn = Get-NetTCPConnection -State Established |
        Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|fe80)' }
if ($conn) {
    Nota "Connessioni verso l'esterno attive: $($conn.Count)"
    foreach ($g in ($conn | Group-Object OwningProcess)) {
        $pr = Get-Process -Id $g.Name
        $nome = "PID $($g.Name)"
        if ($pr) { $nome = $pr.ProcessName }
        $ips = $g.Group | Select-Object -First 3 -ExpandProperty RemoteAddress | Sort-Object -Unique
        $dest = (($ips | ForEach-Object { NomeHost $_ }) -join ', ')
        if ($pr -and $pr.Path -and (EsuPercorsoSospetto $pr.Path) -and -not (FirmaValida $pr.Path)) {
            Allarme "$nome (non firmato, da cartella anomala) collegato a $dest  [SHA256 $(Impronta $pr.Path)]"
        } else { Nota "   $nome -> $dest" }
    }
} else { Nota "Nessuna connessione esterna attiva in questo momento" }

if (Esiste 'Get-LocalUser') {
    $utenti = (Get-LocalUser | Where-Object { $_.Enabled } | Select-Object -ExpandProperty Name) -join ', '
    Nota "Account attivi: $utenti"
    $gruppo = (Get-LocalGroup -SID 'S-1-5-32-544').Name
    $adm = (Get-LocalGroupMember -Group $gruppo).Name -join ', '
    Nota "Amministratori: $adm"
    Nota "Se vedi un account che non hai creato tu, e' un problema serio."
} else { NonDisponibile "Elenco account non disponibile su questo sistema" }

# =====================================================================
Sezione "PARTE B  -  SALUTE DEL PC"
# =====================================================================

Titolo "Dischi: spazio libero"
foreach ($v in $dischi) {
    $tot = [math]::Round($v.Size/1GB,1)
    $lib = [math]::Round($v.SizeRemaining/1GB,1)
    $pct = 0
    if ($v.Size -gt 0) { $pct = [math]::Round(($v.SizeRemaining/$v.Size)*100,1) }
    $et = "$($v.DriveLetter): $lib GB liberi su $tot GB ($pct%)"
    if ($pct -lt 5)      { Problema "SPAZIO QUASI ESAURITO - $et - Windows puo' diventare instabile" }
    elseif ($pct -lt 12) { Avviso "Spazio in esaurimento - $et" }
    else                 { Ok $et }
    if ($v.HealthStatus -and $v.HealthStatus -ne 'Healthy') { Problema "Volume $($v.DriveLetter): stato $($v.HealthStatus)" }
}

Titolo "Dischi: stato fisico (SMART)"
if (-not (Esiste 'Get-PhysicalDisk')) { NonDisponibile "Diagnostica dischi non disponibile su questo sistema" }
else {
    foreach ($d in (Get-PhysicalDisk)) {
        $riga = "$($d.FriendlyName) [$($d.MediaType)] - stato: $($d.HealthStatus)"
        if ($d.HealthStatus -ne 'Healthy') { Problema "DISCO IN SOFFERENZA: $riga - fai subito una copia dei dati" }
        else { Ok $riga }
        $rc = Get-StorageReliabilityCounter -PhysicalDisk $d
        if ($rc) {
            if ($null -ne $rc.Wear -and $rc.Wear -gt 80)          { Avviso "$($d.FriendlyName): usura al $($rc.Wear)% (SSD verso fine vita)" }
            if ($null -ne $rc.Temperature -and $rc.Temperature -gt 60) { Avviso "$($d.FriendlyName): temperatura $($rc.Temperature) gradi" }
            if ($rc.ReadErrorsUncorrected -gt 0)  { Problema "$($d.FriendlyName): $($rc.ReadErrorsUncorrected) errori di lettura non corretti" }
            if ($rc.WriteErrorsUncorrected -gt 0) { Problema "$($d.FriendlyName): $($rc.WriteErrorsUncorrected) errori di scrittura non corretti" }
            if ($null -ne $rc.PowerOnHours) { Nota "   ore di accensione totali: $($rc.PowerOnHours)" }
        }
    }
}

Titolo "Memoria"
$totGB = [math]::Round($os.TotalVisibleMemorySize/1MB,1)
$libGB = [math]::Round($os.FreePhysicalMemory/1MB,1)
$usoPct = [math]::Round((1 - ($os.FreePhysicalMemory/$os.TotalVisibleMemorySize))*100,1)
Nota "RAM totale $totGB GB - libera $libGB GB - in uso $usoPct%"
if ($usoPct -gt 92) { Avviso "Memoria quasi satura ($usoPct%): il PC rallenta" } else { Ok "Uso della memoria nella norma" }
Nota "I 5 processi piu' pesanti:"
foreach ($p in (Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5)) {
    Nota ("   {0,-30} {1,8:N0} MB" -f $p.ProcessName, ($p.WorkingSet64/1MB))
}

Titolo "Errori critici di sistema (ultimi $giorniLog giorni)"
$da = (Get-Date).AddDays(-$giorniLog)
$ev = Get-WinEvent -FilterHashtable @{ LogName='System'; Level=1,2; StartTime=$da } -MaxEvents 500
if (-not $ev) { Ok "Nessun errore critico registrato" }
else {
    Nota "$($ev.Count) eventi di errore o critici. Per origine:"
    foreach ($g in ($ev | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 8)) {
        Nota ("   {0,-40} {1,4}" -f $g.Name, $g.Count)
    }
    $spegn = $ev | Where-Object { $_.Id -eq 41 -or $_.Id -eq 6008 }
    if ($spegn) { Avviso "$($spegn.Count) spegnimenti anomali (blocco, riavvio forzato o mancanza di corrente)" }
    $bsod = $ev | Where-Object { $_.Id -eq 1001 -and $_.ProviderName -like '*BugCheck*' }
    if ($bsod) { Problema "$($bsod.Count) schermate blu registrate" }
    $disco = $ev | Where-Object { $_.ProviderName -match 'disk|Ntfs|storahci|volmgr|stornvme' }
    if ($disco) { Problema "$($disco.Count) errori di disco o file system: possibile disco in sofferenza" }
    $dcom = $ev | Where-Object { $_.ProviderName -like '*DistributedCOM*' }
    if ($dcom) { Nota "   (di cui $($dcom.Count) DistributedCOM: quasi sempre innocui, tipici dopo una reinstallazione)" }
}

Titolo "Crash e file di dump"
$mini = Get-ChildItem -LiteralPath "$env:SystemRoot\Minidump" -Filter *.dmp
if ($mini) {
    $ultimo = ($mini | Sort-Object LastWriteTime -Descending)[0]
    Avviso "$($mini.Count) file di crash presenti. Ultimo: $($ultimo.LastWriteTime.ToString('dd/MM/yyyy HH:mm'))"
    Nota "   Indicano schermate blu passate: spesso driver o memoria RAM difettosa."
} else { Ok "Nessun file di crash" }

Titolo "Driver e periferiche"
$ko = Get-CimInstance Win32_PnPEntity | Where-Object { $null -ne $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 }
if ($ko) { foreach ($k in ($ko | Select-Object -First 10)) { Avviso "Periferica con problemi: $($k.Name) (codice $($k.ConfigManagerErrorCode))" } }
else { Ok "Nessuna periferica in errore" }

Titolo "Aggiornamenti e riavvio in sospeso"
$hot = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hot -and $hot.InstalledOn) {
    $gg = [math]::Round(((Get-Date) - $hot.InstalledOn).TotalDays)
    Nota "Ultimo aggiornamento: $($hot.HotFixID) del $($hot.InstalledOn.ToString('dd/MM/yyyy')) ($gg giorni fa)"
    if ($gg -gt 60) { Avviso "Windows non riceve aggiornamenti da $gg giorni: mancano correzioni di sicurezza" }
    else { Ok "Aggiornamenti recenti" }
} else { Nota "Storico aggiornamenti non disponibile" }
$riavvio = $false
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
    if (Test-Path $k) { $riavvio = $true }
}
if ($riavvio) { Avviso "C'e' un riavvio in sospeso: alcuni aggiornamenti non sono ancora completi" }
else { Ok "Nessun riavvio in sospeso" }

Titolo "Programmi installati di recente (30 giorni)"
$reg = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
$rec = @()
foreach ($r in $reg) {
    foreach ($a in (Get-ItemProperty -Path $r)) {
        if (-not $a.DisplayName -or -not $a.InstallDate) { continue }
        $dt = $null
        try { $dt = [datetime]::ParseExact([string]$a.InstallDate, 'yyyyMMdd', $null) } catch { continue }
        if ($dt -ge (Get-Date).AddDays(-30)) { $rec += [pscustomobject]@{ Nome = $a.DisplayName; Data = $dt } }
    }
}
if ($rec) {
    foreach ($x in ($rec | Sort-Object Data -Descending | Select-Object -First 25)) {
        Nota ("   {0:dd/MM/yyyy}  {1}" -f $x.Data, $x.Nome)
    }
    Nota "Controlla che siano tutti programmi installati da te."
} else { Ok "Nessun programma installato negli ultimi 30 giorni" }

if ($completa) {
    Titolo "Integrita' dei file di sistema (solo scansione completa)"
    $tmpSfc = Join-Path $env:TEMP 'sentinella-sfc.txt'
    $procSfc = Start-Process -FilePath "$env:SystemRoot\System32\sfc.exe" -ArgumentList '/verifyonly' `
               -RedirectStandardOutput $tmpSfc -NoNewWindow -PassThru
    AttendiProcesso $procSfc "verifica dei file di sistema"
    # sfc scrive in UTF-16: letto come testo normale uscirebbe illeggibile.
    $sfc = (Get-Content -LiteralPath $tmpSfc -Encoding Unicode -Raw) -replace "`0", ''
    Remove-Item -LiteralPath $tmpSfc -Force -ErrorAction SilentlyContinue
    $sfcPulito = ($sfc -match 'did not find any integrity violations') -or ($sfc -match 'non ha rilevato alcuna violazione')
    $sfcRotto  = ($sfc -match 'found corrupt files') -or ($sfc -match 'ha rilevato file danneggiati')
    if ($sfcPulito)     { Ok "File di sistema integri" }
    elseif ($sfcRotto)  { Problema "File di sistema danneggiati. Riparabili con: sfc /scannow (da amministratore)" }
    else                { Nota "Esito non interpretabile automaticamente su questa lingua di Windows" }
} else {
    Titolo "Integrita' dei file di sistema"
    Nota "Saltata: e' inclusa solo nella scansione completa (richiede minuti)."
}

# =====================================================================
Sezione "PARTE C  -  ESAME ANTIVIRUS SU TUTTI I DISCHI"
# =====================================================================
Titolo "Esame antivirus"
if (-not (Esiste 'Start-MpScan')) {
    NonDisponibile "Windows Defender non presente: esegui a mano una scansione col tuo antivirus"
} elseif ($completa) {
    Write-Host "  Scansione COMPLETA: ogni file di tutti i dischi." -ForegroundColor Yellow
    Write-Host "  Da 30 minuti a qualche ora. Puoi continuare a usare il PC." -ForegroundColor Gray
    Nota "Modalita': ogni file di tutti i dischi fissi"
    Attendi (Start-MpScan -ScanType FullScan -AsJob) "scansione completa di tutti i dischi"
    Ok "Scansione completa terminata"
} else {
    # La scansione "rapida" di Defender guarda solo il disco di sistema.
    # Qui invece cerchiamo su TUTTI i dischi i file a rischio aggiunti di
    # recente e li facciamo esaminare uno per uno: e' il punto in cui si
    # nascondono gli installer infetti, anche su dischi mai formattati.
    Write-Host "  Cerco file a rischio recenti su tutti i dischi..." -ForegroundColor Gray
    $estRischio = @('.exe','.msi','.bat','.cmd','.ps1','.vbs','.js','.jse','.scr','.hta','.zip','.rar','.7z','.iso','.dll')
    $limite = (Get-Date).AddDays(-45)
    $saltaCartelle = @('Windows','Program Files','Program Files (x86)','ProgramData','$Recycle.Bin','System Volume Information','Recovery')
    $cartelle = @{}
    $nFile = 0
    foreach ($v in $dischi) {
        $radice = "$($v.DriveLetter):\"
        foreach ($sub in (Get-ChildItem -LiteralPath $radice -Force -ErrorAction SilentlyContinue)) {
            if ($sub.PSIsContainer -and ($saltaCartelle -contains $sub.Name)) { continue }
            $target = $sub.FullName
            # Anche questa fase puo' durare minuti: mostrare dove si sta
            # guardando evita che sembri bloccata.
            $mostra = $target
            if ($mostra.Length -gt 52) { $mostra = $mostra.Substring(0, 49) + '...' }
            Write-Host ("`r      esploro  " + $mostra.PadRight(56) + " trovati: $nFile") -NoNewline -ForegroundColor DarkCyan
            $trovati = Get-ChildItem -LiteralPath $target -Recurse -File -Force -Depth 5 -ErrorAction SilentlyContinue |
                       Where-Object { $estRischio -contains $_.Extension.ToLower() -and $_.LastWriteTime -ge $limite }
            foreach ($f in $trovati) { $cartelle[$f.DirectoryName] = $true; $nFile++ }
        }
    }
    Write-Host ("`r" + (" " * 78)) -NoNewline
    Write-Host "`r" -NoNewline
    # Cartelle ad alto rischio del profilo utente, sempre incluse
    foreach ($c in @([Environment]::GetFolderPath('UserProfile') + '\Downloads',
                     [Environment]::GetFolderPath('Desktop'), $env:TEMP)) {
        if (Test-Path -LiteralPath $c) { $cartelle[$c] = $true }
    }
    # Una cartella dentro un'altra gia' in elenco e' ridondante: l'antivirus
    # scende comunque nelle sottocartelle. Senza questo passaggio la stessa
    # roba veniva esaminata piu' volte, allungando inutilmente i tempi.
    $ordinate = @($cartelle.Keys) | Sort-Object { $_.Length }
    $finali = New-Object System.Collections.ArrayList
    foreach ($c in $ordinate) {
        # La radice di un disco (es. "E:\") farebbe scansionare l'INTERO disco:
        # in modalita' rapida esaminiamo i singoli file trovati li' dentro.
        if ($c -match '^[A-Za-z]:\\$') {
            foreach ($f in (Get-ChildItem -LiteralPath $c -File -Force -ErrorAction SilentlyContinue |
                            Where-Object { $estRischio -contains $_.Extension.ToLower() -and $_.LastWriteTime -ge $limite })) {
                [void]$finali.Add($f.FullName)
            }
            continue
        }
        $dentroAdUnaGiaPresente = $false
        foreach ($g in $finali) {
            if ($c.StartsWith($g + '\', [StringComparison]::OrdinalIgnoreCase)) { $dentroAdUnaGiaPresente = $true; break }
        }
        if (-not $dentroAdUnaGiaPresente) { [void]$finali.Add($c) }
    }
    $elenco = @($finali) | Select-Object -First 40
    Nota "$nFile file a rischio recenti in $($cartelle.Count) cartelle su $($dischi.Count) dischi"
    Nota "Dopo aver unito le cartelle annidate: $($finali.Count) punti da esaminare"
    Attendi (Start-MpScan -ScanType QuickScan -AsJob) "memoria e punti di avvio"
    $i = 0
    foreach ($c in $elenco) {
        $i++
        $breve = $c
        if ($breve.Length -gt 48) { $breve = $breve.Substring(0, 22) + '...' + $breve.Substring($breve.Length - 23) }
        Attendi (Start-MpScan -ScanPath $c -ScanType CustomScan -AsJob) ("({0}/{1}) {2}" -f $i, $elenco.Count, $breve)
    }
    Ok "Esaminate memoria, punti di avvio e $($elenco.Count) cartelle su tutti i dischi"
    Nota "Per aprire OGNI file di ogni disco serve la scansione completa."
}

if (Esiste 'Get-MpThreat') {
    $attive = Get-MpThreat | Where-Object { $_.IsActive -eq $true }
    if ($attive) { foreach ($t in $attive) { Allarme "MINACCIA ATTIVA: $($t.ThreatName)" } }
    else { Ok "Nessuna minaccia attiva rilevata" }
}

# =====================================================================
Sezione "PARTE D  -  CONFRONTO CON L'ULTIMA SCANSIONE"
# =====================================================================
Titolo "Novita' dall'ultima scansione"

# Una fotografia sola dice se qualcosa SEMBRA strano. Due fotografie dicono
# cosa e' CAMBIATO, ed e' li' che si vede un'intrusione: un'esclusione
# antivirus comparsa ieri pesa molto piu' della stessa vista una volta sola.
function ImprontaSistema {
    $h = [ordered]@{}

    $avvio = @()
    foreach ($k in $chiavi) {
        $item = Get-ItemProperty -Path $k
        if (-not $item) { continue }
        foreach ($pr in $item.PSObject.Properties) {
            if ($pr.Name -like 'PS*') { continue }
            $avvio += "$($pr.Name) = $($pr.Value)"
        }
    }
    foreach ($cart in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
        foreach ($x in (Get-ChildItem -LiteralPath $cart -File -ErrorAction SilentlyContinue)) { $avvio += "file: $($x.Name)" }
    }
    $h['avvio'] = @($avvio | Sort-Object)

    $tk = @()
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' })) {
        foreach ($a in $t.Actions) { if ($a.Execute) { $tk += "$($t.TaskName) -> $($a.Execute)" } }
    }
    $h['attivita'] = @($tk | Sort-Object)

    $sv = @()
    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) { $sv += "$($s.Name) -> $($s.PathName)" }
    $h['servizi'] = @($sv | Sort-Object)

    $es = @()
    if ((Esiste 'Get-MpPreference') -and $admin) {
        $pf = Get-MpPreference
        foreach ($v in $pf.ExclusionPath)      { if ($v -and $v -notlike 'N/A*') { $es += "cartella: $v" } }
        foreach ($v in $pf.ExclusionProcess)   { if ($v -and $v -notlike 'N/A*') { $es += "processo: $v" } }
        foreach ($v in $pf.ExclusionExtension) { if ($v -and $v -notlike 'N/A*') { $es += "estensione: $v" } }
    }
    $h['esclusioni'] = @($es | Sort-Object)

    $ac = @()
    if (Esiste 'Get-LocalUser') {
        foreach ($u in (Get-LocalUser | Where-Object { $_.Enabled })) { $ac += $u.Name }
        try { foreach ($m in (Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544').Name)) { $ac += "admin: $($m.Name)" } } catch { }
    }
    $h['account'] = @($ac | Sort-Object)

    $dn = @()
    if (Esiste 'Get-DnsClientServerAddress') {
        foreach ($d in (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses })) {
            $dn += "$($d.InterfaceAlias): $($d.ServerAddresses -join ',')"
        }
    }
    $h['dns'] = @($dn | Sort-Object)

    $hs = @()
    foreach ($r in (Get-Content -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue)) {
        if ($r.Trim() -ne '' -and -not $r.Trim().StartsWith('#')) { $hs += $r.Trim() }
    }
    $h['hosts'] = @($hs | Sort-Object)

    $pg = @()
    foreach ($r in $reg) {
        foreach ($a in (Get-ItemProperty -Path $r -ErrorAction SilentlyContinue)) {
            if ($a.DisplayName) { $pg += $a.DisplayName }
        }
    }
    $h['programmi'] = @($pg | Sort-Object -Unique)

    return $h
}

$cartellaStato = Join-Path $env:LOCALAPPDATA 'Sentinella'
$fileStato = Join-Path $cartellaStato 'ultima-scansione.json'
$adesso = ImprontaSistema

$etichette = [ordered]@{
    'esclusioni' = 'esclusioni antivirus'
    'avvio'      = 'programmi in avvio automatico'
    'attivita'   = 'attivita pianificate'
    'servizi'    = 'servizi'
    'account'    = 'account e amministratori'
    'dns'        = 'server DNS'
    'hosts'      = 'righe nel file hosts'
    'programmi'  = 'programmi installati'
}
# Un cambiamento in queste tre categorie e' un campanello serio, non una nota.
$gravi3 = @('esclusioni','hosts','dns')

if (Test-Path -LiteralPath $fileStato) {
    try {
        $prec = Get-Content -LiteralPath $fileStato -Raw | ConvertFrom-Json
        $quando = [datetime]$prec.quando
        $gg = [math]::Round(((Get-Date) - $quando).TotalDays, 1)
        Nota "Ultima scansione: $($quando.ToString('dd/MM/yyyy HH:mm'))  ($gg giorni fa)"
        $cambiamenti = 0
        foreach ($chiave in $etichette.Keys) {
            $vecchi = @()
            if ($prec.impronta.$chiave) { $vecchi = @($prec.impronta.$chiave) }
            $nuovi = @($adesso[$chiave])
            $aggiunti = @($nuovi | Where-Object { $vecchi -notcontains $_ })
            $spariti  = @($vecchi | Where-Object { $nuovi -notcontains $_ })
            foreach ($x in $aggiunti) {
                $cambiamenti++
                $testo = "NUOVO in $($etichette[$chiave]): $x"
                if ($gravi3 -contains $chiave) { Allarme $testo } else { Attenzione $testo }
            }
            foreach ($x in $spariti) {
                $cambiamenti++
                Nota "   rimosso da $($etichette[$chiave]): $x"
            }
        }
        if ($cambiamenti -eq 0) { Ok "Nessun cambiamento: il sistema e' identico all'ultima scansione" }
        else { Nota "Se questi cambiamenti li hai fatti tu, va tutto bene. Altrimenti approfondisci." }
    } catch {
        Attenzione "Impronta precedente illeggibile: la sostituisco con quella di oggi"
    }
} else {
    Ok "Prima scansione: salvo l'impronta del sistema"
    Nota "Dal prossimo controllo Sentinella ti dira' esattamente cosa e' cambiato."
}

try {
    if (-not (Test-Path -LiteralPath $cartellaStato)) { New-Item -ItemType Directory -Path $cartellaStato -Force | Out-Null }
    @{ quando = (Get-Date).ToString('o'); impronta = $adesso } | ConvertTo-Json -Depth 6 |
        Out-File -FilePath $fileStato -Encoding utf8
    Nota "Impronta aggiornata in $fileStato"
} catch {
    Attenzione "Non sono riuscito a salvare l'impronta per il prossimo confronto"
}

# =====================================================================
$durata = [math]::Round(((Get-Date) - $inizio).TotalMinutes,1)
Sezione "REPORT FINALE  -  scansione $tipo"

$gravi = $allarmi.Count + $problemi.Count
$lievi = $sospetti.Count + $avvisi.Count

function Riquadro($righe, $colore) {
    $L = 68
    Write-Host ("   +" + ("-" * $L) + "+") -ForegroundColor $colore
    foreach ($r in $righe) {
        $sp = $L - 2 - $r.Length
        if ($sp -lt 0) { $sp = 0 }
        Write-Host ("   | " + $r + (" " * $sp) + " |") -ForegroundColor $colore
    }
    Write-Host ("   +" + ("-" * $L) + "+") -ForegroundColor $colore
}

Write-Host ""
if ($gravi -eq 0 -and $lievi -eq 0) {
    Riquadro @("VERDETTO:   TUTTO REGOLARE",
               "Nessun segno di infezione, nessun problema di salute.") 'Green'
} elseif ($gravi -eq 0) {
    $p = "punti da guardare"
    if ($lievi -eq 1) { $p = "punto da guardare" }
    Riquadro @("VERDETTO:   NESSUN PROBLEMA GRAVE",
               "$lievi $p, senza fretta.") 'Yellow'
} else {
    $g = "PROBLEMI GRAVI"
    if ($gravi -eq 1) { $g = "PROBLEMA GRAVE" }
    Riquadro @("VERDETTO:   $gravi $g",
               "Le voci in rosso qui sotto vanno affrontate.") 'Red'
}

# Quadro di TUTTI i controlli, non solo di quelli andati storti: cosi'
# si vede a colpo d'occhio cosa e' stato guardato e come e' andata.
Write-Host ""
Write-Host "   QUADRO DEI $TOTPASSI CONTROLLI" -ForegroundColor White
$sezPrec = ''
foreach ($k in $esiti.Keys) {
    $sez = $sezioneDi[$k]
    if ($sez -ne $sezPrec) {
        Write-Host ""
        Write-Host "     $sez" -ForegroundColor DarkCyan
        $sezPrec = $sez
    }
    switch ($esiti[$k]) {
        0       { $sim = '[ OK ]'; $col = 'Green' }
        1       { $sim = '[ !! ]'; $col = 'Yellow' }
        2       { $sim = '[ XX ]'; $col = 'Red' }
        default { $sim = '[ -- ]'; $col = 'DarkGray' }
    }
    Write-Host ("       {0}  {1}" -f $sim, $k) -ForegroundColor $col
}
Write-Host ""
Write-Host "       [ OK ] a posto    [ !! ] da guardare    [ XX ] grave    [ -- ] non applicabile" -ForegroundColor DarkGray

if ($gravi -gt 0 -or $lievi -gt 0) {
    Write-Host ""
    Write-Host "   COSA E' EMERSO" -ForegroundColor White
    if ($allarmi.Count)  { Write-Host ""; Write-Host "     SICUREZZA - GRAVE" -ForegroundColor Red;          foreach ($x in $allarmi)  { Write-Host "       [XX] $x" -ForegroundColor Red } }
    if ($problemi.Count) { Write-Host ""; Write-Host "     SALUTE DEL PC - GRAVE" -ForegroundColor Red;      foreach ($x in $problemi) { Write-Host "       [XX] $x" -ForegroundColor Red } }
    if ($sospetti.Count) { Write-Host ""; Write-Host "     SICUREZZA - da guardare" -ForegroundColor Yellow; foreach ($x in $sospetti) { Write-Host "       [!!] $x" -ForegroundColor Yellow } }
    if ($avvisi.Count)   { Write-Host ""; Write-Host "     SALUTE DEL PC - da guardare" -ForegroundColor Yellow; foreach ($x in $avvisi) { Write-Host "       [!!] $x" -ForegroundColor Yellow } }
}

Write-Host ""
Write-Host ("   " + ("=" * 68)) -ForegroundColor DarkGray
Write-Host "   Scansione $tipo   -   $TOTPASSI controlli   -   $durata minuti" -ForegroundColor DarkGray
Write-Host "   Dischi esaminati: $lettere" -ForegroundColor DarkGray
Write-Host ("   " + ("=" * 68)) -ForegroundColor DarkGray
Write-Host ""
Write-Host "   ONESTA' SUI LIMITI" -ForegroundColor DarkGray
Write-Host "   Sentinella controlla i nascondigli e i guasti piu' comuni, non" -ForegroundColor DarkGray
Write-Host "   tutti. Un esito pulito rende un problema molto improbabile, non" -ForegroundColor DarkGray
Write-Host "   impossibile: gli antivirus non riconoscono i malware appena" -ForegroundColor DarkGray
Write-Host "   confezionati. Vale sempre anche il buon senso su cosa apri e" -ForegroundColor DarkGray
Write-Host "   da chi arriva." -ForegroundColor DarkGray
Write-Host ""

# --- salvataggio su richiesta ---------------------------------------
Write-Host ("   " + ("-" * 68)) -ForegroundColor DarkGray
Write-Host "   Vuoi salvare il report?" -ForegroundColor White
Write-Host "     [T] file di testo     [H] pagina web     [E] entrambi     [N] no" -ForegroundColor DarkGray
$risposta = Read-Host "   Scegli"
$vuoleTxt  = $risposta -match '^\s*[TtEeSsYy]'
$vuoleHtml = $risposta -match '^\s*[HhEe]'
if ($vuoleTxt -or $vuoleHtml) {
    # Il Desktop puo' essere reindirizzato su OneDrive: chiediamolo a Windows.
    $desktop = [Environment]::GetFolderPath('Desktop')
    $base = Join-Path $desktop ("Sentinella-Report-" + (Get-Date -Format 'yyyyMMdd-HHmm'))
    $file = "$base.txt"
    $testa = @()
    $testa += "============================================================"
    $testa += " SENTINELLA $VERSIONE - REPORT           by lozy"
    $testa += " Scansione $tipo del $(Get-Date -Format 'dd/MM/yyyy HH:mm')"
    $testa += " Durata $durata minuti - dischi esaminati: $lettere"
    $testa += "============================================================"
    $testa += ""
    $testa += "VERDETTO"
    if ($gravi -eq 0 -and $lievi -eq 0)  { $testa += "  TUTTO REGOLARE" }
    elseif ($gravi -eq 0)                { $testa += "  Nessun problema grave, $lievi da guardare" }
    else                                 { $testa += "  $gravi problemi gravi, $lievi da guardare" }
    $testa += ""
    $testa += "QUADRO DEI $TOTPASSI CONTROLLI"
    $sp = ''
    foreach ($k in $esiti.Keys) {
        if ($sezioneDi[$k] -ne $sp) { $testa += ""; $testa += "  $($sezioneDi[$k])"; $sp = $sezioneDi[$k] }
        switch ($esiti[$k]) {
            0       { $s = '[ OK ]' }
            1       { $s = '[ !! ]' }
            2       { $s = '[ XX ]' }
            default { $s = '[ -- ]' }
        }
        $testa += "    $s  $k"
    }
    $testa += ""
    $testa += "COSA E' EMERSO"
    $testa += "  Sicurezza - grave      : $($allarmi.Count)"
    foreach ($x in $allarmi)  { $testa += "    [XX] $x" }
    $testa += "  Salute PC - grave      : $($problemi.Count)"
    foreach ($x in $problemi) { $testa += "    [XX] $x" }
    $testa += "  Sicurezza - da guardare: $($sospetti.Count)"
    foreach ($x in $sospetti) { $testa += "    [!!] $x" }
    $testa += "  Salute PC - da guardare: $($avvisi.Count)"
    foreach ($x in $avvisi)   { $testa += "    [!!] $x" }
    $testa += ""
    $testa += "============================================================"
    $testa += " DETTAGLIO COMPLETO DI OGNI CONTROLLO"
    $testa += "============================================================"
    Write-Host ""
    if ($vuoleTxt) {
        ($testa + $diario) | Out-File -FilePath $file -Encoding utf8
        Write-Host "   Testo salvato in:  $file" -ForegroundColor Cyan
    }
    if ($vuoleHtml) {
        function Esc($s) {
            if ($null -eq $s) { return '' }
            return ([string]$s).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
        }
        $fileH = "$base.html"
        if ($gravi -eq 0 -and $lievi -eq 0) { $vClasse = 'ok';   $vTesto = 'TUTTO REGOLARE'; $vSub = 'Nessun segno di infezione, nessun problema di salute.' }
        elseif ($gravi -eq 0)               { $vClasse = 'warn'; $vTesto = 'NESSUN PROBLEMA GRAVE'; $vSub = "$lievi punti da guardare, senza fretta." }
        else                                { $vClasse = 'bad';  $vTesto = "$gravi PROBLEMI GRAVI"; $vSub = 'Le voci in rosso vanno affrontate.' }

        $h = New-Object System.Text.StringBuilder
        [void]$h.AppendLine('<!DOCTYPE html><html lang="it"><head><meta charset="utf-8">')
        [void]$h.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
        [void]$h.AppendLine("<title>Sentinella - report $tipo</title><style>")
        [void]$h.AppendLine('*{box-sizing:border-box}body{margin:0;background:#0d1117;color:#c9d1d9;font:15px/1.6 "Segoe UI",system-ui,sans-serif}')
        [void]$h.AppendLine('.wrap{max-width:960px;margin:0 auto;padding:32px 20px 64px}')
        [void]$h.AppendLine('h1{font-size:34px;letter-spacing:.22em;margin:0;color:#58a6ff}')
        [void]$h.AppendLine('.sub{color:#8b949e;font-size:14px;margin:4px 0 28px}')
        [void]$h.AppendLine('.verd{border-radius:10px;padding:20px 24px;margin:0 0 28px;border-left:6px solid}')
        [void]$h.AppendLine('.ok{background:#0d2818;border-color:#2ea043}.warn{background:#2b2411;border-color:#d29922}.bad{background:#2d1214;border-color:#f85149}')
        [void]$h.AppendLine('.verd b{display:block;font-size:22px;margin-bottom:4px}')
        [void]$h.AppendLine('h2{font-size:13px;letter-spacing:.16em;color:#8b949e;text-transform:uppercase;margin:34px 0 12px;border-bottom:1px solid #21262d;padding-bottom:8px}')
        [void]$h.AppendLine('table{width:100%;border-collapse:collapse}td{padding:7px 10px;border-bottom:1px solid #161b22}')
        [void]$h.AppendLine('td.b{width:96px}.sec{color:#58a6ff;font-weight:600;padding-top:18px}')
        [void]$h.AppendLine('.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:700}')
        [void]$h.AppendLine('.g{background:#0d2818;color:#3fb950}.y{background:#2b2411;color:#d29922}.r{background:#2d1214;color:#f85149}.n{background:#161b22;color:#8b949e}')
        [void]$h.AppendLine('li{margin:5px 0}code{background:#161b22;padding:1px 6px;border-radius:4px;font-size:13px}')
        [void]$h.AppendLine('pre{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;overflow-x:auto;font-size:12.5px;color:#8b949e;white-space:pre-wrap}')
        [void]$h.AppendLine('footer{margin-top:44px;color:#6e7681;font-size:13px;text-align:center;border-top:1px solid #21262d;padding-top:18px}')
        [void]$h.AppendLine('footer b{color:#58a6ff}</style></head><body><div class="wrap">')
        [void]$h.AppendLine('<h1>SENTINELLA</h1>')
        [void]$h.AppendLine("<div class=""sub"">sicurezza e salute del tuo PC &middot; v$VERSIONE &middot; scansione <b>$tipo</b> del $(Get-Date -Format 'dd/MM/yyyy HH:mm') &middot; $durata minuti &middot; dischi: $(Esc $lettere)</div>")
        [void]$h.AppendLine("<div class=""verd $vClasse""><b>$vTesto</b>$vSub</div>")
        [void]$h.AppendLine("<h2>Quadro dei $TOTPASSI controlli</h2><table>")
        $sp2 = ''
        foreach ($k in $esiti.Keys) {
            if ($sezioneDi[$k] -ne $sp2) {
                [void]$h.AppendLine("<tr><td colspan=""2"" class=""sec"">$(Esc $sezioneDi[$k])</td></tr>")
                $sp2 = $sezioneDi[$k]
            }
            switch ($esiti[$k]) {
                0       { $cl = 'g'; $tx = 'OK' }
                1       { $cl = 'y'; $tx = 'DA VEDERE' }
                2       { $cl = 'r'; $tx = 'GRAVE' }
                default { $cl = 'n'; $tx = 'N/D' }
            }
            [void]$h.AppendLine("<tr><td class=""b""><span class=""badge $cl"">$tx</span></td><td>$(Esc $k)</td></tr>")
        }
        [void]$h.AppendLine('</table>')
        if ($gravi -gt 0 -or $lievi -gt 0) {
            [void]$h.AppendLine('<h2>Cosa e&#39; emerso</h2><ul>')
            foreach ($x in $allarmi)  { [void]$h.AppendLine("<li><span class=""badge r"">SICUREZZA</span> $(Esc $x)</li>") }
            foreach ($x in $problemi) { [void]$h.AppendLine("<li><span class=""badge r"">SALUTE</span> $(Esc $x)</li>") }
            foreach ($x in $sospetti) { [void]$h.AppendLine("<li><span class=""badge y"">SICUREZZA</span> $(Esc $x)</li>") }
            foreach ($x in $avvisi)   { [void]$h.AppendLine("<li><span class=""badge y"">SALUTE</span> $(Esc $x)</li>") }
            [void]$h.AppendLine('</ul>')
        }
        [void]$h.AppendLine('<h2>Dettaglio completo</h2><pre>')
        foreach ($r in $diario) { [void]$h.AppendLine((Esc $r)) }
        [void]$h.AppendLine('</pre>')
        [void]$h.AppendLine('<footer>Generato da <b>Sentinella</b> v' + $VERSIONE + ' &mdash; by <b>lozy</b><br>Controlla i nascondigli e i guasti piu&#39; comuni, non tutti: un esito pulito rende un problema molto improbabile, non impossibile.</footer>')
        [void]$h.AppendLine('</div></body></html>')
        [System.IO.File]::WriteAllText($fileH, $h.ToString(), (New-Object System.Text.UTF8Encoding $false))
        Write-Host "   Pagina salvata in: $fileH" -ForegroundColor Cyan
    }
} else {
    Write-Host ""
    Write-Host "   Nessun file creato: il report resta solo qui a schermo." -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "   " -NoNewline
Write-Host "Sentinella v$VERSIONE" -NoNewline -ForegroundColor DarkCyan
Write-Host "  ~  " -NoNewline -ForegroundColor DarkGray
Write-Host "by " -NoNewline -ForegroundColor DarkGray
Write-Host "lozy" -ForegroundColor Cyan
Write-Host ""
Write-Host "   Premi INVIO per chiudere..." -ForegroundColor DarkGray
Read-Host
