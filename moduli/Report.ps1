# =====================================================================
#  SENTINELLA - Report finale (schermo, testo, pagina web, JSON)
# =====================================================================

# "Cosa faccio adesso": una spiegazione semplice e un'azione concreta per
# ogni controllo che ha trovato qualcosa. La chiave e' il PRINCIPIO del
# titolo del controllo: alcuni titoli cambiano a runtime (es. "ultimi 7
# giorni" / "ultimi 30 giorni").
$glossario = [ordered]@{
    'Antivirus' = @{
        Cosa = "L'antivirus non e' del tutto attivo o aggiornato: e' la prima difesa, e se e' spento o vecchio il resto del PC e' scoperto."
        Fai  = "Impostazioni > Privacy e sicurezza > Sicurezza di Windows > Protezione da virus e minacce. Riattiva la protezione in tempo reale se e' spenta; se le definizioni sono vecchie, premi Verifica aggiornamenti."
    }
    'Esclusioni antivirus' = @{
        Cosa = "Qualcuno ha detto all'antivirus di NON controllare una cartella, un programma o un tipo di file. E' il primo trucco che usano i malware appena si installano, per rendersi invisibili."
        Fai  = "Se non l'hai messa tu: Sicurezza di Windows > Protezione da virus e minacce > Gestisci impostazioni > Aggiungi o rimuovi esclusioni, e cancellala. Poi lancia una scansione Completa."
    }
    'Storico minacce' = @{
        Cosa = "Defender ha gia' trovato qualcosa in passato, e risulta ancora non risolto."
        Fai  = "Sicurezza di Windows > Protezione da virus e minacce > Cronologia protezione: trova la voce e scegli Rimuovi o Metti in quarantena. Se non si lascia rimuovere, chiedi aiuto a qualcuno di fiducia."
    }
    'Firewall' = @{
        Cosa = "Un profilo del firewall e' spento: il PC accetta connessioni che normalmente bloccherebbe."
        Fai  = "Sicurezza di Windows > Firewall e protezione rete, e riattiva il profilo segnalato."
    }
    'Programmi in avvio automatico' = @{
        Cosa = "Un programma parte da solo a ogni accensione da una cartella insolita o tramite uno script. Non e' per forza un problema, ma e' un posto classico dove si nasconde chi vuole restare anche dopo un riavvio."
        Fai  = "Task Manager (Ctrl+Shift+Esc) > scheda Avvio: trova la voce segnalata. Se non riconosci il programma, disattivalo da li'. Se lo riconosci, alla prossima scansione rispondi 'si' quando Sentinella te lo chiede: non ti verra' piu' segnalato finche' il file resta identico."
    }
    'Nascondigli di avvio avanzati' = @{
        Cosa = "E' stata modificata una delle poche impostazioni di Windows che fanno partire un programma insieme al sistema stesso, ancora prima del desktop. Le usano quasi solo malware o software di sicurezza legittimo."
        Fai  = "Non e' una cosa da sistemare a mano. Fai girare Sentinella in modalita' Completa, e se il segnale resta, fatti aiutare da qualcuno esperto prima di usare il PC per email o banca."
    }
    "Attivita' pianificate" = @{
        Cosa = "C'e' un'attivita' pianificata che fa partire un programma non firmato da una cartella insolita: un altro modo per far ripartire qualcosa a ogni accensione o a orari fissi. Se Sentinella dice che fa parte di un programma installato, e' quasi sempre il suo controllo aggiornamenti."
        Fai  = "Se riconosci il programma, alla prossima scansione Rapida rispondi 'si' quando te lo chiede. Se no: cerca 'Utilita' di pianificazione' nel menu Start, trova l'attivita' con lo stesso nome, tasto destro > Disattiva."
    }
    'Processi in esecuzione' = @{
        Cosa = "C'e' un programma in esecuzione ADESSO, non firmato digitalmente, partito da una cartella insolita: potrebbe essere attivo sul PC in questo momento."
        Fai  = "Task Manager > cerca il processo per nome > tasto destro > Apri percorso file, per capire da dove viene. Nel dubbio, tasto destro > Termina attivita', e non riaprirlo finche' non sai cos'e'."
    }
    'Servizi e persistenza avanzata' = @{
        Cosa = "Un servizio di Windows (gira sempre, anche senza che tu apra nulla) non e' firmato e parte da una cartella insolita, oppure c'e' una 'sottoscrizione' di sistema non standard: un modo poco conosciuto per restare attivi a lungo su un PC."
        Fai  = "E' tecnico: la cosa piu' sicura e' far vedere il report a qualcuno esperto, o cercare online il nome esatto del servizio segnalato prima di toccarlo."
    }
    'Comandi incollati' = @{
        Cosa = "Tra i comandi scritti o incollati sul PC ce n'e' uno che scarica ed esegue codice da internet: e' il trucco 'ClickFix' dei finti CAPTCHA."
        Fai  = "Se l'hai scritto tu per installare qualcosa che conosci, va bene. Se l'hai incollato perche' una pagina te lo chiedeva, da un altro dispositivo cambia le password e chiudi le sessioni attive."
    }
    'File scaricati di recente' = @{
        Cosa = "Sono arrivati da internet programmi o script senza firma digitale: e' la strada di quasi tutti gli infostealer."
        Fai  = "Se non sei sicuro di cosa sia, non aprirlo: cerca l'impronta SHA256 su virustotal.com."
    }
    'Programmi avviati di recente' = @{
        Cosa = "Windows ha annotato l'avvio di programmi senza firma da cartelle a rischio, o di programmi poi cancellati."
        Fai  = "Se non riconosci la voce, da un altro dispositivo cambia le password e chiudi le sessioni attive."
    }
    'Discord' = @{
        Cosa = "Il file con cui Discord si avvia e' stato modificato: trucco tipico dei ladri di account."
        Fai  = "Se non usi mod, reinstalla Discord dal sito ufficiale e cambia la password da un altro dispositivo."
    }
    'Estensioni del browser' = @{
        Cosa = "Risulta un'estensione installata di recente nel browser, non di serie. Le estensioni possono leggere tutto quello che scrivi e vedi online, password comprese."
        Fai  = "Nel browser: tre puntini > Estensioni > Gestisci estensioni. Controlla quella segnalata; se non l'hai installata tu di proposito, rimuovila."
    }
    'Rete: file hosts, proxy, DNS' = @{
        Cosa = "Qualcosa sta deviando il traffico internet del PC: un sito che apri potrebbe non essere quello vero. E' una tecnica classica per rubare password o mostrare pagine false."
        Fai  = "Per il proxy: Impostazioni > Rete e Internet > Proxy, disattiva quello che non hai impostato tu. Per hosts o DNS, se non li hai modificati tu di proposito, fatti aiutare: sono due punti delicati da toccare a mano."
    }
    'Connessioni di rete e account' = @{
        Cosa = "C'e' un programma non firmato, da una cartella insolita, che sta comunicando con internet in questo momento, oppure risulta un account amministratore che non ricordi di aver creato."
        Fai  = "Per la connessione: stessa procedura di Processi in esecuzione. Per un account sconosciuto: Impostazioni > Account > Altri utenti, rimuovilo se non l'hai creato tu e cambia subito la tua password."
    }
    'Dischi: spazio libero' = @{
        Cosa = "Il disco e' quasi pieno. Non e' un problema di sicurezza, ma Windows puo' diventare instabile o lento sotto un certo margine di spazio libero."
        Fai  = "Impostazioni > Sistema > Archiviazione ti mostra cosa occupa di piu'. Svuota il Cestino e disinstalla cio' che non usi."
    }
    'Dischi: stato fisico' = @{
        Cosa = "Il disco segnala segni di usura o errori: potrebbe guastarsi, e a differenza di un'infezione un disco rotto puo' far perdere i dati per sempre."
        Fai  = "Fai SUBITO una copia dei file importanti su un altro disco o servizio cloud, prima di qualunque altra cosa. Poi valuta la sostituzione del disco."
    }
    'Memoria' = @{
        Cosa = "La RAM e' quasi satura: il PC rallenta perche' e' costretto a scrivere su disco al posto della memoria veloce."
        Fai  = "Chiudi i programmi che non usi. Se succede spesso, valuta di aggiungere piu' RAM."
    }
    'Errori critici di sistema' = @{
        Cosa = "Windows ha registrato schermate blu o errori del disco."
        Fai  = "Se capita spesso, aggiorna i driver dal sito del produttore della scheda video o madre. Se persiste, potrebbe essere un problema hardware da far controllare."
    }
    'Errori hardware' = @{
        Cosa = "Un componente hardware ha segnalato un errore che non ha potuto correggere: guasto o instabilita', non un virus."
        Fai  = "Riporta overclock e undervolt ai valori di fabbrica, aggiorna il BIOS, e se continua fai controllare il pezzo."
    }
    'Crash e file di dump' = @{
        Cosa = "Ci sono tracce di schermate blu recenti."
        Fai  = "Se e' capitato una volta sola, non preoccuparti. Se e' frequente, aggiorna i driver o fai controllare l'hardware."
    }
    'Driver e periferiche' = @{
        Cosa = "Una periferica (stampante, scheda audio, dispositivo USB...) non funziona correttamente."
        Fai  = "Se e' un dispositivo USB non riconosciuto: scollegalo e ricollegalo, prova un'altra porta o un altro cavo. Altrimenti: 'Gestione dispositivi' dal menu Start, voce con il punto esclamativo giallo, tasto destro > Aggiorna driver."
    }
    'Aggiornamenti e riavvio in sospeso' = @{
        Cosa = "Windows non si aggiorna da tempo, oppure un aggiornamento e' a meta' e aspetta un riavvio. Gli aggiornamenti spesso chiudono falle di sicurezza vere."
        Fai  = "Impostazioni > Windows Update > Verifica aggiornamenti, installa quello che trovi e riavvia quando richiesto."
    }
    'Programmi installati di recente' = @{
        Cosa = "Uno o piu' programmi installati di recente non hanno una firma digitale: non e' per forza un problema, ma su questi non c'e' un editore verificato a garantire per loro."
        Fai  = "Guarda solo quelli segnalati 'NON firmato digitalmente': se non ricordi di averli installati tu, cercali online prima di lasciarli sul PC."
    }
    "Integrita' dei file di sistema" = @{
        Cosa = "Alcuni file di sistema di Windows risultano danneggiati o modificati rispetto all'originale."
        Fai  = "Prompt dei comandi come amministratore, poi scrivi: sfc /scannow  e premi Invio. Windows prova a ripararli da solo."
    }
    'Esame antivirus' = @{
        Cosa = "Windows Defender ha trovato una minaccia ATTIVA durante la scansione."
        Fai  = "Sicurezza di Windows > Protezione da virus e minacce > Cronologia protezione, e segui le indicazioni per rimuoverla. Poi cambia le password dei servizi importanti da un altro dispositivo."
    }
    "Novita' dall'ultima scansione" = @{
        Cosa = "Qualcosa nel sistema e' cambiato rispetto all'ultima volta che hai usato Sentinella: potresti averlo fatto tu (un'installazione, un aggiornamento), oppure no."
        Fai  = "Guarda cosa risulta cambiato nel dettaglio: se riconosci ogni voce come cosa fatta da te, va tutto bene. Se anche una sola non la riconosci, trattala come un allarme vero."
    }
}
$spiegazioneNonVerificato = @{
    Cosa = "Sentinella non e' riuscita a guardare una parte di questo controllo (permessi mancanti, un servizio di Windows spento, o un errore di lettura). Non e' un problema trovato, ma nemmeno un via libera."
    Fai  = "Riavvia Sentinella con SENTINELLA.bat (chiede i permessi di amministratore). Se resta non verificato, il motivo e' scritto accanto al controllo: un servizio di sicurezza spento senza motivo e' gia' di per se' un segnale da guardare."
}
function Spiega($titoloEsatto) {
    if ($script:spiegazioniDinamiche.ContainsKey($titoloEsatto)) { return $script:spiegazioniDinamiche[$titoloEsatto] }
    if ($script:glossario.Contains($titoloEsatto)) { return $script:glossario[$titoloEsatto] }
    foreach ($chiave in $script:glossario.Keys) {
        if ($titoloEsatto.StartsWith($chiave)) { return $script:glossario[$chiave] }
    }
    return $null
}

function SimboloEsito([int]$e) {
    switch ($e) {
        0 { return @{ Sim = '[ OK ]'; Col = 'Green';    Web = 'g'; Tx = 'OK' } }
        1 { return @{ Sim = '[ !! ]'; Col = 'Yellow';   Web = 'y'; Tx = 'DA VEDERE' } }
        2 { return @{ Sim = '[ XX ]'; Col = 'Red';      Web = 'r'; Tx = 'GRAVE' } }
        4 { return @{ Sim = '[ ?? ]'; Col = 'Magenta';  Web = 'm'; Tx = 'NON VERIFICATO' } }
        default { return @{ Sim = '[ -- ]'; Col = 'DarkGray'; Web = 'n'; Tx = 'N/A' } }
    }
}

function Verdetto {
    $gravi = $script:allarmi.Count + $script:problemi.Count
    $lievi = $script:sospetti.Count + $script:avvisi.Count
    $nonVer = @($script:esiti.Keys | Where-Object { [int]$script:esiti[$_] -eq 4 -or $script:incompleti[$_] }).Count
    $v = [ordered]@{ Gravi = $gravi; Lievi = $lievi; NonVerificati = $nonVer; Codice = 0; Titolo = ''; Sotto = ''; Classe = 'ok'; Colore = 'Green' }
    if ($gravi -gt 0) {
        $g = "PROBLEMI GRAVI"; if ($gravi -eq 1) { $g = "PROBLEMA GRAVE" }
        $v.Titolo = "$gravi $g"; $v.Sotto = "Le voci in rosso qui sotto vanno affrontate."; $v.Classe = 'bad'; $v.Colore = 'Red'; $v.Codice = 2
    } elseif ($lievi -gt 0) {
        $p = "punti da guardare"; if ($lievi -eq 1) { $p = "punto da guardare" }
        $v.Titolo = "NESSUN PROBLEMA GRAVE"; $v.Sotto = "$lievi $p, senza fretta."; $v.Classe = 'warn'; $v.Colore = 'Yellow'; $v.Codice = 1
    } elseif ($nonVer -gt 0) {
        $c = "controlli non verificati"; if ($nonVer -eq 1) { $c = "controllo non verificato" }
        $v.Titolo = "NESSUN PROBLEMA TROVATO"; $v.Sotto = "Ma $nonVer ${c}: non posso dire 'tutto regolare'."; $v.Classe = 'unk'; $v.Colore = 'Magenta'; $v.Codice = 3
    } else {
        $v.Titolo = "TUTTO REGOLARE"; $v.Sotto = "Nessun segno di infezione, nessun problema di salute."
    }
    if ($gravi -gt 0 -or $lievi -gt 0) {
        if ($nonVer -gt 0) { $v.Sotto += " ($nonVer controlli non verificati)" }
    }
    return $v
}

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

function ReportSchermo($v) {
    Write-Host ""
    Riquadro @("VERDETTO:   $($v.Titolo)", $v.Sotto) $v.Colore
    Write-Host ""
    Write-Host "   QUADRO DEI $($script:TOTPASSI) CONTROLLI" -ForegroundColor White
    $sezPrec = ''
    foreach ($k in $script:esiti.Keys) {
        $sez = $script:sezioneDi[$k]
        if ($sez -ne $sezPrec) { Write-Host ""; Write-Host "     $sez" -ForegroundColor DarkCyan; $sezPrec = $sez }
        $s = SimboloEsito ([int]$script:esiti[$k])
        $extra = ''
        if ($script:incompleti[$k] -and [int]$script:esiti[$k] -ne 4) { $extra = '   (in parte non verificato)' }
        Write-Host ("       {0}  {1}{2}" -f $s.Sim, $k, $extra) -ForegroundColor $s.Col
    }
    Write-Host ""
    Write-Host "       [ OK ] a posto   [ !! ] da guardare   [ XX ] grave   [ ?? ] non verificato   [ -- ] non applicabile" -ForegroundColor DarkGray

    if ($v.Gravi -gt 0 -or $v.Lievi -gt 0 -or $script:mancati.Count -gt 0) {
        Write-Host ""
        Write-Host "   COSA E' EMERSO" -ForegroundColor White
        if ($script:allarmi.Count)  { Write-Host ""; Write-Host "     SICUREZZA - GRAVE" -ForegroundColor Red;          foreach ($x in $script:allarmi)  { Write-Host "       [XX] $x" -ForegroundColor Red } }
        if ($script:problemi.Count) { Write-Host ""; Write-Host "     SALUTE DEL PC - GRAVE" -ForegroundColor Red;      foreach ($x in $script:problemi) { Write-Host "       [XX] $x" -ForegroundColor Red } }
        if ($script:sospetti.Count) { Write-Host ""; Write-Host "     SICUREZZA - da guardare" -ForegroundColor Yellow; foreach ($x in $script:sospetti) { Write-Host "       [!!] $x" -ForegroundColor Yellow } }
        if ($script:avvisi.Count)   { Write-Host ""; Write-Host "     SALUTE DEL PC - da guardare" -ForegroundColor Yellow; foreach ($x in $script:avvisi) { Write-Host "       [!!] $x" -ForegroundColor Yellow } }
        if ($script:mancati.Count)  { Write-Host ""; Write-Host "     NON VERIFICATO (ne' buono ne' cattivo: non ho potuto guardare)" -ForegroundColor Magenta; foreach ($x in $script:mancati) { Write-Host "       [??] $x" -ForegroundColor Magenta } }

        Write-Host ""
        Write-Host "   COSA FARE ADESSO" -ForegroundColor White
        foreach ($k in $script:esiti.Keys) {
            $e = [int]$script:esiti[$k]
            if ($e -notin @(1, 2, 4)) { continue }
            $sp = Spiega $k
            if ($e -eq 4) { $sp = $script:spiegazioneNonVerificato }
            if (-not $sp) { continue }
            $s = SimboloEsito $e
            Write-Host ""
            Write-Host "     $k" -ForegroundColor $s.Col
            Write-Host "       Cosa significa: " -NoNewline -ForegroundColor DarkGray
            Write-Host $sp.Cosa -ForegroundColor Gray
            Write-Host "       Cosa fare:      " -NoNewline -ForegroundColor DarkGray
            Write-Host $sp.Fai -ForegroundColor White
        }
    }
    Write-Host ""
    Write-Host ("   " + ("=" * 68)) -ForegroundColor DarkGray
    Write-Host "   Scansione $($script:tipo)   -   $($script:TOTPASSI) controlli   -   $($script:durata) minuti" -ForegroundColor DarkGray
    Write-Host "   Dischi esaminati: $($script:lettere)" -ForegroundColor DarkGray
    Write-Host ("   " + ("=" * 68)) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "   ONESTA' SUI LIMITI" -ForegroundColor DarkGray
    Write-Host "   Sentinella controlla i nascondigli e i guasti piu' comuni, non" -ForegroundColor DarkGray
    Write-Host "   tutti. Un esito pulito rende un problema molto improbabile, non" -ForegroundColor DarkGray
    Write-Host "   impossibile: gli antivirus non riconoscono i malware appena" -ForegroundColor DarkGray
    Write-Host "   confezionati. Vale sempre anche il buon senso su cosa apri e" -ForegroundColor DarkGray
    Write-Host "   da chi arriva." -ForegroundColor DarkGray
    Write-Host ""
}

# Il JSON e' la versione "per programmi" del report: confrontabile nel tempo,
# leggibile da altri strumenti. Una copia va SEMPRE nello storico locale
# (%LOCALAPPDATA%\Sentinella\storico), anche se non salvi altro.
function DatiJson($v) {
    $controlli = foreach ($k in $script:esiti.Keys) {
        $s = SimboloEsito ([int]$script:esiti[$k])
        [ordered]@{ titolo = $k; sezione = $script:sezioneDi[$k]; esito = $s.Tx; codice = [int]$script:esiti[$k]; inParteNonVerificato = [bool]$script:incompleti[$k] }
    }
    return [ordered]@{
        strumento = 'Sentinella'; versione = $script:VERSIONE; formato = 1
        data = (Get-Date).ToString('o'); modalita = $script:tipo; durataMinuti = $script:durata
        amministratore = [bool]$script:admin; dischi = $script:lettere
        verdetto = [ordered]@{ titolo = $v.Titolo; dettaglio = $v.Sotto; codiceUscita = $v.Codice; gravi = $v.Gravi; daGuardare = $v.Lievi; nonVerificati = $v.NonVerificati }
        controlli = @($controlli)
        reperti = @($script:reperti)
    }
}
function SalvaStorico($dati) {
    try {
        $c = Join-Path $script:cartellaDati 'storico'
        if (-not (Test-Path -LiteralPath $c)) { New-Item -ItemType Directory -Path $c -Force | Out-Null }
        $f = Join-Path $c ("scansione-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".json")
        $dati | ConvertTo-Json -Depth 8 | Out-File -FilePath $f -Encoding utf8 -ErrorAction Stop
        # Si tengono le ultime 50: lo storico non deve crescere all'infinito.
        Get-ChildItem -LiteralPath $c -Filter 'scansione-*.json' | Sort-Object Name -Descending | Select-Object -Skip 50 |
            Remove-Item -Force -ErrorAction SilentlyContinue
        return $f
    } catch { return $null }
}

function Esc($s) {
    if ($null -eq $s) { return '' }
    return ([string]$s).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

function SalvaReport($v, [bool]$vuoleTxt, [bool]$vuoleHtml, [bool]$vuoleJson, $dati) {
    # Il Desktop puo' essere reindirizzato su OneDrive: chiediamolo a Windows.
    $cartellaReport = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Sentinella-Report'
    $nomeFile = "Sentinella-Report-" + (Get-Date -Format 'yyyyMMdd-HHmm')
    if ($vuoleTxt) {
        $c = Join-Path $cartellaReport 'Testo'
        if (-not (Test-Path -LiteralPath $c)) { New-Item -ItemType Directory -Path $c -Force | Out-Null }
        $file = Join-Path $c "$nomeFile.txt"
        $t = @()
        $t += "============================================================"
        $t += " SENTINELLA $($script:VERSIONE) - REPORT           by lozy"
        $t += " Scansione $($script:tipo) del $(Get-Date -Format 'dd/MM/yyyy HH:mm')"
        $t += " Durata $($script:durata) minuti - dischi esaminati: $($script:lettere)"
        $t += "============================================================"
        $t += ""
        $t += "VERDETTO"
        $t += "  $($v.Titolo) - $($v.Sotto)"
        $t += ""
        $t += "QUADRO DEI $($script:TOTPASSI) CONTROLLI"
        $sp = ''
        foreach ($k in $script:esiti.Keys) {
            if ($script:sezioneDi[$k] -ne $sp) { $t += ""; $t += "  $($script:sezioneDi[$k])"; $sp = $script:sezioneDi[$k] }
            $s = SimboloEsito ([int]$script:esiti[$k])
            $extra = ''; if ($script:incompleti[$k] -and [int]$script:esiti[$k] -ne 4) { $extra = '  (in parte non verificato)' }
            $t += "    $($s.Sim)  $k$extra"
        }
        $t += ""
        $t += "COSA E' EMERSO"
        $t += "  Sicurezza - grave      : $($script:allarmi.Count)"
        foreach ($x in $script:allarmi)  { $t += "    [XX] $x" }
        $t += "  Salute PC - grave      : $($script:problemi.Count)"
        foreach ($x in $script:problemi) { $t += "    [XX] $x" }
        $t += "  Sicurezza - da guardare: $($script:sospetti.Count)"
        foreach ($x in $script:sospetti) { $t += "    [!!] $x" }
        $t += "  Salute PC - da guardare: $($script:avvisi.Count)"
        foreach ($x in $script:avvisi)   { $t += "    [!!] $x" }
        $t += "  Non verificato         : $($script:mancati.Count)"
        foreach ($x in $script:mancati)  { $t += "    [??] $x" }
        $t += ""
        $t += "COSA FARE ADESSO"
        foreach ($k in $script:esiti.Keys) {
            $e = [int]$script:esiti[$k]
            if ($e -notin @(1, 2, 4)) { continue }
            $sp0 = Spiega $k
            if ($e -eq 4) { $sp0 = $script:spiegazioneNonVerificato }
            if (-not $sp0) { continue }
            $t += ""
            $t += "  $k"
            $t += "    Cosa significa: $($sp0.Cosa)"
            $t += "    Cosa fare:      $($sp0.Fai)"
        }
        $t += ""
        $t += "============================================================"
        $t += " DETTAGLIO COMPLETO DI OGNI CONTROLLO"
        $t += "============================================================"
        ($t + $script:diario) | Out-File -FilePath $file -Encoding utf8
        Scrivi "   Testo salvato in:  $file" Cyan
    }
    if ($vuoleJson) {
        $c = Join-Path $cartellaReport 'JSON'
        if (-not (Test-Path -LiteralPath $c)) { New-Item -ItemType Directory -Path $c -Force | Out-Null }
        $fileJ = Join-Path $c "$nomeFile.json"
        $dati | ConvertTo-Json -Depth 8 | Out-File -FilePath $fileJ -Encoding utf8
        Scrivi "   JSON salvato in:   $fileJ" Cyan
    }
    if ($vuoleHtml) {
        $c = Join-Path $cartellaReport 'Pagine web'
        if (-not (Test-Path -LiteralPath $c)) { New-Item -ItemType Directory -Path $c -Force | Out-Null }
        $fileH = Join-Path $c "$nomeFile.html"
        $h = New-Object System.Text.StringBuilder
        [void]$h.AppendLine('<!DOCTYPE html><html lang="it"><head><meta charset="utf-8">')
        [void]$h.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
        [void]$h.AppendLine("<title>Sentinella - report $($script:tipo)</title><style>")
        [void]$h.AppendLine('*{box-sizing:border-box}body{margin:0;background:#0d1117;color:#c9d1d9;font:15px/1.6 "Segoe UI",system-ui,sans-serif}')
        [void]$h.AppendLine('.wrap{max-width:960px;margin:0 auto;padding:32px 20px 64px}')
        [void]$h.AppendLine('h1{font-size:34px;letter-spacing:.22em;margin:0;color:#58a6ff}')
        [void]$h.AppendLine('.sub{color:#8b949e;font-size:14px;margin:4px 0 28px}')
        [void]$h.AppendLine('.verd{border-radius:10px;padding:20px 24px;margin:0 0 28px;border-left:6px solid}')
        [void]$h.AppendLine('.ok{background:#0d2818;border-color:#2ea043}.warn{background:#2b2411;border-color:#d29922}.bad{background:#2d1214;border-color:#f85149}.unk{background:#221a2e;border-color:#bc8cff}')
        [void]$h.AppendLine('.verd b{display:block;font-size:22px;margin-bottom:4px}')
        [void]$h.AppendLine('h2{font-size:13px;letter-spacing:.16em;color:#8b949e;text-transform:uppercase;margin:34px 0 12px;border-bottom:1px solid #21262d;padding-bottom:8px}')
        [void]$h.AppendLine('table{width:100%;border-collapse:collapse}td{padding:7px 10px;border-bottom:1px solid #161b22}')
        [void]$h.AppendLine('td.b{width:150px}.sec{color:#58a6ff;font-weight:600;padding-top:18px}')
        [void]$h.AppendLine('.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:700}')
        [void]$h.AppendLine('.g{background:#0d2818;color:#3fb950}.y{background:#2b2411;color:#d29922}.r{background:#2d1214;color:#f85149}.n{background:#161b22;color:#8b949e}.m{background:#221a2e;color:#bc8cff}')
        [void]$h.AppendLine('li{margin:5px 0;overflow-wrap:anywhere}.part{color:#bc8cff;font-size:12px}')
        [void]$h.AppendLine('.spiega{background:#161b22;border-left:4px solid;border-radius:6px;padding:14px 16px;margin:10px 0}')
        [void]$h.AppendLine('.spiega.r{border-color:#f85149}.spiega.y{border-color:#d29922}.spiega.m{border-color:#bc8cff}')
        [void]$h.AppendLine('.spiega h3{margin:0 0 8px;font-size:15px;color:#e6edf3}.spiega p{margin:4px 0}.spiega b{color:#8b949e;font-weight:600}')
        [void]$h.AppendLine('pre{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;overflow-x:auto;font-size:12.5px;color:#8b949e;white-space:pre-wrap;overflow-wrap:anywhere}')
        [void]$h.AppendLine('footer{margin-top:44px;color:#6e7681;font-size:13px;text-align:center;border-top:1px solid #21262d;padding-top:18px}')
        [void]$h.AppendLine('footer b{color:#58a6ff}</style></head><body><div class="wrap">')
        [void]$h.AppendLine('<h1>SENTINELLA</h1>')
        [void]$h.AppendLine("<div class=""sub"">sicurezza e salute del tuo PC &middot; v$($script:VERSIONE) &middot; scansione <b>$($script:tipo)</b> del $(Get-Date -Format 'dd/MM/yyyy HH:mm') &middot; $($script:durata) minuti &middot; dischi: $(Esc $script:lettere)</div>")
        [void]$h.AppendLine("<div class=""verd $($v.Classe)""><b>$(Esc $v.Titolo)</b>$(Esc $v.Sotto)</div>")
        [void]$h.AppendLine("<h2>Quadro dei $($script:TOTPASSI) controlli</h2><table>")
        $sp2 = ''
        foreach ($k in $script:esiti.Keys) {
            if ($script:sezioneDi[$k] -ne $sp2) { [void]$h.AppendLine("<tr><td colspan=""2"" class=""sec"">$(Esc $script:sezioneDi[$k])</td></tr>"); $sp2 = $script:sezioneDi[$k] }
            $s = SimboloEsito ([int]$script:esiti[$k])
            $extra = ''; if ($script:incompleti[$k] -and [int]$script:esiti[$k] -ne 4) { $extra = ' <span class="part">(in parte non verificato)</span>' }
            [void]$h.AppendLine("<tr><td class=""b""><span class=""badge $($s.Web)"">$($s.Tx)</span></td><td>$(Esc $k)$extra</td></tr>")
        }
        [void]$h.AppendLine('</table>')
        if ($v.Gravi -gt 0 -or $v.Lievi -gt 0 -or $script:mancati.Count -gt 0) {
            [void]$h.AppendLine('<h2>Cosa e&#39; emerso</h2><ul>')
            foreach ($x in $script:allarmi)  { [void]$h.AppendLine("<li><span class=""badge r"">SICUREZZA</span> $(Esc $x)</li>") }
            foreach ($x in $script:problemi) { [void]$h.AppendLine("<li><span class=""badge r"">SALUTE</span> $(Esc $x)</li>") }
            foreach ($x in $script:sospetti) { [void]$h.AppendLine("<li><span class=""badge y"">SICUREZZA</span> $(Esc $x)</li>") }
            foreach ($x in $script:avvisi)   { [void]$h.AppendLine("<li><span class=""badge y"">SALUTE</span> $(Esc $x)</li>") }
            foreach ($x in $script:mancati)  { [void]$h.AppendLine("<li><span class=""badge m"">NON VERIFICATO</span> $(Esc $x)</li>") }
            [void]$h.AppendLine('</ul><h2>Cosa fare adesso</h2>')
            foreach ($k in $script:esiti.Keys) {
                $e = [int]$script:esiti[$k]
                if ($e -notin @(1, 2, 4)) { continue }
                $sp1 = Spiega $k
                if ($e -eq 4) { $sp1 = $script:spiegazioneNonVerificato }
                if (-not $sp1) { continue }
                $s = SimboloEsito $e
                [void]$h.AppendLine("<div class=""spiega $($s.Web)""><h3>$(Esc $k)</h3><p><b>Cosa significa:</b> $(Esc $sp1.Cosa)</p><p><b>Cosa fare:</b> $(Esc $sp1.Fai)</p></div>")
            }
        }
        [void]$h.AppendLine('<h2>Dettaglio completo</h2><pre>')
        foreach ($r in $script:diario) { [void]$h.AppendLine((Esc $r)) }
        [void]$h.AppendLine('</pre>')
        [void]$h.AppendLine('<footer>Generato da <b>Sentinella</b> v' + $script:VERSIONE + ' &mdash; by <b>lozy</b><br>Controlla i nascondigli e i guasti piu&#39; comuni, non tutti: un esito pulito rende un problema molto improbabile, non impossibile.</footer>')
        [void]$h.AppendLine('</div></body></html>')
        [System.IO.File]::WriteAllText($fileH, $h.ToString(), (New-Object System.Text.UTF8Encoding $false))
        Scrivi "   Pagina salvata in: $fileH" Cyan
    }
}

# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC8ccyK2iOL9Vlm
# 9V9mlaxOHNQjediV6I9hdjsiKbMhzqCCBCowggQmMIICjqADAgECAhBsFNOb1/0T
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAko63a49imvBto
# T+zmD2D8lRwuoGZyZm7HH7i0Th9oDjANBgkqhkiG9w0BAQEFAASCAYBZkLr8s/kY
# JFF0KvGg57YV2kyNReNMQs/KnIv5l6mFMb+EptxpB2kIik/TO0cDjMgrjzGUrAfE
# msaQNKVhbQ1T35vSHNWCnPkEBPWyxo7j80/YSKxAN5n/8h+Bsk0nQHaG0Eymh3u+
# K4LxeOKUo8kioNzfE8LhRGOZgGHxF0vWNwsBMUS+0YW8Zvb6uajJXy0DoB5TZEhq
# RE1QgLY9bDUFXIrjUDv7L178FkfyJa9pxZnLGKpj6rA8ysb0w6a+6Te1UjT24dD/
# 2StXP7caeWzW+wAS6f8B0nFJi/HnT0BsIwJCY5rCR/7ieVb9R/O1v9Sy4RrqpH9Q
# /UvYULn3GsSLhHP9sYB+CW9jeqI2hr+1c7PxIfpki8fPIWSXPkq0oAbodLlVlHyh
# YiJ4T3kQkkiQDVf+hDriXq2BppQC7Xb5MsxSxaY+xJ+PO0v8tprvQHwaFgc19DWI
# Jr0sAaOOiS0va2QWZlI+0HCI9qCXncTvXPXkDTDa6UM+hnYispahH2o=
# SIG # End signature block
