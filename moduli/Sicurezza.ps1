# =====================================================================
#  SENTINELLA - Parte A: sicurezza
#  Ogni funzione C_* e' un controllo; il motore (EseguiControllo, in
#  Base.ps1) la esegue e ne decide l'esito finale.
# =====================================================================

function C_Sistema {
    if (-not $script:os) { NonVerificato "Informazioni di Windows non leggibili"; return }
    $giorniOS = [math]::Round(((Get-Date) - $script:installato).TotalDays, 1)
    Nota "Windows  : $($script:os.Caption) build $($script:os.BuildNumber)"
    if ($script:cs) { Nota "Computer : $($script:cs.Manufacturer) $($script:cs.Model)" }
    Nota "Installato: $($script:installato.ToString('dd/MM/yyyy HH:mm'))  ($giorniOS giorni fa)"
    Nota "Acceso da : $([math]::Round(((Get-Date) - $script:os.LastBootUpTime).TotalHours,1)) ore"
    if (-not $script:admin) { NonVerificato "Sentinella non gira come amministratore: diversi controlli saranno parziali" }
    else { Ok "Informazioni di sistema raccolte, permessi di amministratore presenti" }
}

function C_Antivirus {
    if (-not (Esiste 'Get-MpComputerStatus')) {
        NonDisponibile "Windows Defender non presente (probabile antivirus di terze parti)"
        Attenzione "Verifica a mano che il tuo antivirus sia attivo e aggiornato"
        return
    }
    $l = Leggi { Get-MpComputerStatus } "Stato di Windows Defender"
    if ($null -eq $l -or $l.Count -eq 0) { if ($null -ne $l) { NonVerificato "Stato di Defender vuoto: il servizio potrebbe essere spento" }; return }
    $mp = $l[0]
    if ($mp.RealTimeProtectionEnabled) { Ok "Protezione in tempo reale ATTIVA" }
    else { Allarme "Protezione in tempo reale DISATTIVATA (e' la prima cosa che un malware spegne)" }
    if ($mp.AntivirusEnabled) { Ok "Antivirus attivo" } else { Allarme "Antivirus NON attivo" }
    if ($mp.AntivirusSignatureLastUpdated) {
        $etaDef = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays
        if ($etaDef -le 3) { Ok "Definizioni aggiornate ($([math]::Round($etaDef,1)) giorni)" }
        elseif ($etaDef -le 14) { Attenzione "Definizioni vecchie di $([math]::Round($etaDef,1)) giorni" }
        else { Allarme "Definizioni vecchie di $([math]::Round($etaDef,1)) giorni: l'antivirus e' quasi cieco" }
    } else { NonVerificato "Data delle definizioni antivirus non disponibile" }
    if ($mp.IsTamperProtected) { Ok "Protezione da manomissione attiva" }
    else { Attenzione "Protezione da manomissione disattivata" }
}

function EsclusioniDefender {
    $esc = @()
    $pref = Leggi { Get-MpPreference } "Impostazioni di Defender"
    if ($null -eq $pref) { return $null }
    if ($pref.Count -eq 0) { NonVerificato "Impostazioni di Defender vuote"; return $null }
    $p = $pref[0]
    foreach ($v in $p.ExclusionPath)      { if ($v -and $v -notlike 'N/A*') { $esc += "cartella: $v" } }
    foreach ($v in $p.ExclusionProcess)   { if ($v -and $v -notlike 'N/A*') { $esc += "processo: $v" } }
    foreach ($v in $p.ExclusionExtension) { if ($v -and $v -notlike 'N/A*') { $esc += "estensione: $v" } }
    foreach ($v in $p.ExclusionIpAddress) { if ($v -and $v -notlike 'N/A*') { $esc += "indirizzo IP: $v" } }
    # Senza amministratore Defender risponde "N/A: Must be an administrator":
    # sembrerebbe "nessuna esclusione", invece non ha detto niente.
    $nascoste = @($p.ExclusionPath) + @($p.ExclusionProcess) | Where-Object { $_ -like 'N/A*' }
    if ($nascoste) { NonVerificato "Defender non mostra le esclusioni senza permessi di amministratore"; return $null }
    return ,@($esc)
}

function C_Esclusioni {
    if (-not (Esiste 'Get-MpPreference')) { NonDisponibile "Defender non presente, controllo non applicabile"; return }
    $esc = EsclusioniDefender
    if ($null -eq $esc) { return }
    if ($esc.Count -eq 0) { Ok "Nessuna esclusione impostata"; return }
    foreach ($e in $esc) { Allarme "Esclusione -> $e" }
    Nota "Un'esclusione dice all'antivirus di NON controllare quel punto."
    Nota "Se non l'hai messa tu, e' un segnale molto serio."
}

function C_StoricoMinacce {
    if (-not (Esiste 'Get-MpThreatDetection')) { NonDisponibile "Non applicabile senza Defender"; return }
    $minacce = Leggi { Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending } "Cronologia minacce di Defender"
    if ($null -eq $minacce) { return }
    if ($minacce.Count -eq 0) { Ok "Nessuna minaccia mai rilevata su questo sistema"; return }
    $catalogo = Leggi { Get-MpThreat } "Catalogo minacce di Defender"
    if ($null -eq $catalogo) { $catalogo = @() }
    Nota "$($minacce.Count) rilevamenti in archivio. Ultimi 10:"
    # Non ci si affida a ThreatStatusID (codice interno non garantito
    # stabile): si verificano fatti diretti - il file e' ancora li'? e'
    # mai stato eseguito? la rimozione e' riuscita?
    $peggiorStorico = 0
    foreach ($m in ($minacce | Select-Object -First 10)) {
        $infoMinaccia = $catalogo | Where-Object { $_.ThreatID -eq $m.ThreatID } | Select-Object -First 1
        $nome = $infoMinaccia.ThreatName
        if (-not $nome) { $nome = "ID $($m.ThreatID)" }
        $q = $m.InitialDetectionTime.ToString('dd/MM/yyyy HH:mm')
        $ancoraPresente = $false
        foreach ($r in $m.Resources) {
            $p = $r -replace '^file:_', ''
            if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) { $ancoraPresente = $true }
        }
        $eseguita = $infoMinaccia -and $infoMinaccia.DidThreatExecute
        if ($ancoraPresente -or ($eseguita -and -not $m.ActionSuccess)) {
            Attenzione "$q - $nome - il file e' ancora presente o la rimozione non e' riuscita"
            if ($peggiorStorico -lt 2) { $peggiorStorico = 2 }
        } elseif ($nome -like 'VulnerableDriver:*') {
            Nota "   $q - $nome - driver legittimo con una falla nota (non un virus), bloccato da Defender"
        } elseif ($eseguita) {
            Nota "   $q - $nome - ha girato sul PC prima di essere bloccata e rimossa con successo"
            if ($peggiorStorico -lt 1) { $peggiorStorico = 1 }
        } else {
            Nota "   $q - $nome - rilevata e rimossa, mai eseguita sul PC"
        }
    }
    if ($peggiorStorico -eq 0) {
        Ok "Le minacce passate risultano rimosse e nessun malware risulta aver girato sul PC"
    } elseif ($peggiorStorico -eq 1) {
        Attenzione "Una minaccia ha girato sul PC prima di essere rimossa (dettaglio qui sopra)"
        SpiegaDinamica `
            "Nella cronologia c'e' una minaccia che ha effettivamente girato sul PC prima che Defender la bloccasse e rimuovesse. E' stata neutralizzata, ma essendo stata in esecuzione potrebbe aver fatto qualcosa prima di essere fermata." `
            "Non serve rimuovere nulla, Defender l'ha gia' fatto. Per sicurezza, cambia le password dei servizi importanti (email, banca) da un altro dispositivo, e chiudi le sessioni attive (Discord, Steam, Google): un infostealer ruba anche le sessioni, che scavalcano la verifica in due passaggi."
    } else {
        SpiegaDinamica `
            "Nella cronologia c'e' una minaccia il cui file risulta ancora presente sul disco, o la cui rimozione da parte di Defender non e' andata a buon fine." `
            "Sicurezza di Windows > Protezione da virus e minacce > Cronologia protezione, apri la voce indicata sopra e prova 'Rimuovi'. Se non si lascia rimuovere, disconnetti la rete e chiedi aiuto a qualcuno di fiducia prima di continuare a usare il PC."
    }
}

function C_Firewall {
    if (-not (Esiste 'Get-NetFirewallProfile')) { NonDisponibile "Controllo non disponibile su questo sistema"; return }
    $profili = Leggi { Get-NetFirewallProfile } "Profili del firewall"
    if ($null -eq $profili) { return }
    if ($profili.Count -eq 0) { NonVerificato "Windows non ha restituito nessun profilo del firewall"; return }
    foreach ($p in $profili) {
        if ($p.Enabled) { Ok "Profilo $($p.Name): attivo" }
        else { Attenzione "Profilo $($p.Name): DISATTIVATO" }
    }
}

function C_Avvio {
    $nAvvio = 0; $sospetti = 0
    foreach ($k in $script:chiaviAvvio) {
        if (-not (Test-Path $k)) { continue }
        $item = Leggi { Get-ItemProperty -Path $k } "Chiave di avvio $k"
        if ($null -eq $item -or $item.Count -eq 0) { continue }
        foreach ($p in $item[0].PSObject.Properties) {
            if ($script:proprietaPS -contains $p.Name) { continue }
            $nAvvio++
            $val = [string]$p.Value
            if (ComandoSospetto $val) { $sospetti++; Allarme "Avvio tramite comando sospetto: $($p.Name) -> $val" }
            elseif (EsuPercorsoSospetto $val) {
                if (FirmaValida $val) { Nota "   $($p.Name) - firmato da $(NomeFirmatario $val)" }
                elseif (-not (Test-Path -LiteralPath (EstraiEseguibile $val))) { Nota "   $($p.Name) - punta a un file che non esiste piu': voce orfana, innocua" }
                else { $sospetti++; ValutaNonFirmato $val "Avvio automatico '$($p.Name)'" }
            }
            elseif ($val -match '\.(vbs|js|jse|bat|cmd|ps1|scr|hta)(\"|\s|$)') { $sospetti++; Allarme "Avvio tramite script: $($p.Name) -> $val" }
            else { Nota "   $($p.Name)" }
        }
    }
    foreach ($cart in $script:cartelleEsecuzioneAutomatica) {
        if (-not (Test-Path -LiteralPath $cart)) { continue }
        foreach ($x in (Get-ChildItem -LiteralPath $cart -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $nAvvio++; $sospetti++
            $dest = $x.FullName
            if ($x.Extension -eq '.lnk') {
                try { $dest = (New-Object -ComObject WScript.Shell).CreateShortcut($x.FullName).TargetPath } catch { }
            }
            if ($dest -and $dest -ne $x.FullName -and (FirmaValida $dest)) { Nota "   cartella Esecuzione automatica: $($x.Name) -> firmato da $(NomeFirmatario $dest)" ; $sospetti-- }
            else { Attenzione "File nella cartella Esecuzione automatica: $($x.FullName) -> $dest" }
        }
    }
    Nota "Totale voci in avvio: $nAvvio"
    if ($nAvvio -gt 25) { Avviso "Molti programmi in avvio ($nAvvio): il computer parte piu' lento" }
    if ($sospetti -eq 0) { Ok "Nessuna voce di avvio sospetta" }
}

function C_NascondigliAvanzati {
    # Le chiavi qui sotto sono poco note e quasi sempre vuote o con un valore
    # fisso: sono il posto dove si mette chi non vuole comparire nell'elenco
    # ovvio dei programmi in avvio.
    $wl = Leggi { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' } "Chiave Winlogon"
    if ($wl -and $wl.Count -gt 0) {
        $w = $wl[0]
        if ($w.Shell -and $w.Shell.Trim() -ne 'explorer.exe') { Allarme "Winlogon Shell modificata: '$($w.Shell)' invece di 'explorer.exe'" }
        else { Ok "Winlogon Shell regolare (explorer.exe)" }
        $ui = "$($w.Userinit)".Trim().TrimEnd(',')
        if ($ui -and $ui -notmatch '(?i)^[A-Z]:\\Windows\\system32\\userinit\.exe$') { Allarme "Winlogon Userinit modificato: '$ui'" }
        else { Ok "Winlogon Userinit regolare" }
    }
    $ai = Leggi { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' } "Chiave AppInit"
    if ($ai -and $ai.Count -gt 0) {
        if ($ai[0].AppInit_DLLs -and $ai[0].AppInit_DLLs.Trim()) { Allarme "AppInit_DLLs non vuoto: '$($ai[0].AppInit_DLLs)' - carica una libreria in ogni programma" }
        else { Ok "AppInit_DLLs vuoto (nessuna libreria iniettata ovunque)" }
    }
    # IFEO: nato per agganciare un debugger a un programma, viene usato per
    # far partire altro al posto suo (o per impedire l'avvio degli antivirus).
    $chiaviIfeo = Leggi { Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' } "Chiave IFEO"
    if ($null -ne $chiaviIfeo) {
        $ifeo = 0
        foreach ($k in $chiaviIfeo) {
            $d = (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($d) { $ifeo++; Allarme "Dirottamento IFEO su '$($k.PSChildName)' -> $d" }
        }
        if ($ifeo -eq 0) { Ok "Nessun dirottamento IFEO" }
    }
    $bho = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' -ErrorAction SilentlyContinue)
    foreach ($k in $bho) { Nota "   componente aggiuntivo di sistema: $($k.PSChildName)" }
    if ($bho.Count -eq 0) { Ok "Nessun componente aggiuntivo agganciato a Explorer" }
}

function C_Attivita {
    $elenco = Leggi { Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } } "Elenco delle attivita' pianificate"
    if ($null -eq $elenco) { return }
    if ($elenco.Count -eq 0) { NonVerificato "Windows non ha restituito nessuna attivita' pianificata (anomalo: ce ne sono sempre)"; return }
    $b = 0
    foreach ($t in $elenco) {
        foreach ($a in $t.Actions) {
            $ex = $a.Execute
            if (-not $ex) { continue }
            $ex = $ex.Trim('"')
            $riga = "$($a.Execute) $($a.Arguments)".Trim()
            if (ComandoSospetto $riga) {
                $b++; Allarme "Attivita' '$($t.TaskName)' lancia un comando sospetto: $riga"
            } elseif ((EsuPercorsoSospetto $ex) -or ((EstraiEseguibile $ex) -match '\.(vbs|js|jse|hta|scr)$')) {
                if (FirmaValida $ex) { Nota "   $($t.TaskName) -> firmato da $(NomeFirmatario $ex)" }
                elseif (-not (Test-Path -LiteralPath (EstraiEseguibile $ex))) { Nota "   $($t.TaskName) -> punta a un file che non esiste piu' (attivita' orfana)" }
                else { $b++; ValutaNonFirmato $ex "Attivita' '$($t.TaskName)' ($riga)" }
            }
        }
    }
    if ($b -eq 0) { Ok "Nessuna attivita' pianificata sospetta su $($elenco.Count)" }
}

function C_Processi {
    $proc = Leggi { Get-Process | Where-Object { $_.Path } | Sort-Object Path -Unique } "Elenco dei processi"
    if ($null -eq $proc) { return }
    $b = 0
    # Per percorso, non per nome: un malware chiamato "svchost" in una cartella utente
    # verrebbe scartato come doppione del vero svchost di Windows.
    foreach ($p in $proc) {
        $q = "`"$($p.Path)`""
        if (EsuPercorsoSospetto $q) {
            if (FirmaValida $q) { Nota "   $($p.ProcessName) - fuori da Programmi ma firmato da $(NomeFirmatario $q)" }
            elseif (GiaRiconosciuto $q $p.ProcessName) { }
            else {
                $b++
                $prop = ProprietarioDi $q
                if ($prop) { $t = "$($p.ProcessName) NON firmato, in esecuzione da $($p.Path) - parte del programma installato '$prop'  [SHA256 $(Impronta $q)]"; $d = "probabilmente parte di '$prop'" }
                else { $t = "$($p.ProcessName) NON firmato, in esecuzione da $($p.Path)  [SHA256 $(Impronta $q)]"; $d = "in esecuzione ora, fuori da Programmi" }
                Attenzione $t
                if ((StatoConferma $q) -ne 'no') { ProponiFile $q $d 1 $t }
            }
        }
    }
    if ($b -eq 0) { Ok "Nessun processo non firmato da cartelle anomale ($($proc.Count) controllati)" }
}

function C_Servizi {
    $servizi = Leggi { Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.PathName } } "Elenco dei servizi"
    if ($null -ne $servizi) {
        if ($servizi.Count -eq 0) { NonVerificato "Windows non ha restituito nessun servizio (anomalo)" }
        else {
            $b = 0
            foreach ($s in $servizi) {
                $pn = $s.PathName
                if (ComandoSospetto $pn) { $b++; Allarme "Servizio '$($s.Name)' lancia un comando sospetto: $pn" }
                elseif (EsuPercorsoSospetto $pn) {
                    if (FirmaValida $pn) { Nota "   $($s.Name) -> firmato da $(NomeFirmatario $pn)" }
                    elseif (-not (Test-Path -LiteralPath (EstraiEseguibile $pn))) { Nota "   $($s.Name) -> file non piu' presente (servizio orfano)" }
                    else { $b++; ValutaNonFirmato $pn "Servizio '$($s.Name)'" }
                }
            }
            if ($b -eq 0) { Ok "Nessun servizio non firmato in cartelle utente ($($servizi.Count) controllati)" }
        }
    }
    $wmiNoti = @('SCM Event Log Filter', 'BVTFilter')
    $wmi = Leggi { Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop } "Sottoscrizioni WMI"
    if ($null -ne $wmi) {
        $strani = @($wmi | Where-Object { $wmiNoti -notcontains $_.Name })
        if ($strani.Count -gt 0) { foreach ($w in $strani) { Attenzione "Sottoscrizione WMI non standard: $($w.Name) (tecnica di persistenza avanzata)" } }
        else { Ok "Nessuna persistenza WMI sospetta" }
    }
}

function C_Estensioni {
    # Un'estensione malevola legge tutto quello che scrivi nel browser, password
    # comprese, e non compare da nessuna parte tra i programmi installati.
    $browser = @(
        @{ Nome = 'Chrome';  Base = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
        @{ Nome = 'Edge';    Base = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
        @{ Nome = 'Brave';   Base = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" },
        @{ Nome = 'Vivaldi'; Base = "$env:LOCALAPPDATA\Vivaldi\User Data" },
        @{ Nome = 'Opera';   Base = "$env:APPDATA\Opera Software\Opera Stable" },
        @{ Nome = 'Opera GX'; Base = "$env:APPDATA\Opera Software\Opera GX Stable" }
    )
    $recenteEst = (Get-Date).AddDays(-45)
    # Su un Windows appena installato tutto risulta "recente": conta solo
    # cio' che e' comparso DOPO la configurazione iniziale del computer.
    $sogliaSetup = $script:installato.AddDays(2)
    if ($recenteEst -lt $sogliaSetup) { $recenteEst = $sogliaSetup }
    $totEst = 0; $nuoveEst = 0; $trovatoBrowser = $false
    foreach ($b in $browser) {
        if (-not (Test-Path -LiteralPath $b.Base)) { continue }
        $trovatoBrowser = $true
        $nb = 0
        # Opera tiene le estensioni direttamente nella cartella base, gli altri per profilo.
        $profili = @(Get-ChildItem -LiteralPath $b.Base -Directory -ErrorAction SilentlyContinue)
        if (Test-Path -LiteralPath (Join-Path $b.Base 'Extensions')) { $profili += Get-Item -LiteralPath $b.Base }
        foreach ($prof in $profili) {
            $dirEst = Join-Path $prof.FullName 'Extensions'
            if (-not (Test-Path -LiteralPath $dirEst)) { continue }
            $impostazioni = ImpostazioniEstensioni $prof.FullName
            foreach ($est in (Get-ChildItem -LiteralPath $dirEst -Directory -ErrorAction SilentlyContinue)) {
                $ver = Get-ChildItem -LiteralPath $est.FullName -Directory -ErrorAction SilentlyContinue |
                       Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if (-not $ver) { continue }
                $totEst++; $nb++
                $nome = $est.Name
                $man = Join-Path $ver.FullName 'manifest.json'
                if (Test-Path -LiteralPath $man) {
                    try {
                        $j = Get-Content -LiteralPath $man -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
                        $nome = NomeEstensione $j $ver.FullName $est.Name
                    } catch { }
                }
                $infoEst = $impostazioni[$est.Name]
                if ($infoEst -and $infoEst.was_installed_by_default) { continue }
                $dataEst = $ver.LastWriteTime
                if ($infoEst -and $infoEst.first_install_time) {
                    try { $dataEst = [datetime]::FromFileTimeUtc([long]$infoEst.first_install_time * 10).ToLocalTime() } catch { }
                }
                if ($dataEst -ge $recenteEst) {
                    $nuoveEst++
                    Attenzione "$($b.Nome): estensione installata di recente - '$nome' ($($dataEst.ToString('dd/MM/yyyy')))"
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
}
# La data della cartella cambia a ogni aggiornamento automatico: la data vera di
# installazione, e se l'estensione e' di serie, stanno nelle impostazioni del browser.
function ImpostazioniEstensioni($cartellaProfilo) {
    $imp = @{}
    foreach ($nomeFile in @('Secure Preferences', 'Preferences')) {
        $f = Join-Path $cartellaProfilo $nomeFile
        if (-not (Test-Path -LiteralPath $f)) { continue }
        try {
            $j = Get-Content -LiteralPath $f -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
            foreach ($pr in $j.extensions.settings.PSObject.Properties) {
                if (-not $imp.ContainsKey($pr.Name) -or $pr.Value.first_install_time) { $imp[$pr.Name] = $pr.Value }
            }
        } catch { }
    }
    return $imp
}
function NomeEstensione($manifesto, $cartellaVersione, $idEstensione) {
    if (-not $manifesto -or -not $manifesto.name) { return $idEstensione }
    if ($manifesto.name -notlike '__MSG_*') { return $manifesto.name }
    $chiave = $manifesto.name -replace '^__MSG_|__$', ''
    $fileLingua = Join-Path $cartellaVersione "_locales\$($manifesto.default_locale)\messages.json"
    if (Test-Path -LiteralPath $fileLingua) {
        try {
            $testi = Get-Content -LiteralPath $fileLingua -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
            foreach ($t in $testi.PSObject.Properties) { if ($t.Name -ieq $chiave) { return $t.Value.message } }
        } catch { }
    }
    return $idEstensione
}

function C_Rete {
    $fileHosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hosts = Leggi { Get-Content -LiteralPath $fileHosts } "File hosts"
    if ($null -ne $hosts) {
        $righe = @($hosts | Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') })
        if ($righe.Count -eq 0) { Ok "File hosts pulito (nessun sito dirottato)" }
        else { foreach ($r in $righe) { Allarme "Riga nel file hosts: $r" } }
    }
    $pIE = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($pIE.ProxyEnable -eq 1) { Allarme "PROXY ATTIVO ($($pIE.ProxyServer)): puo' leggere tutto il traffico" }
    else { Ok "Nessun proxy configurato" }
    if ($pIE.AutoConfigURL) { Allarme "Configurazione proxy scaricata da: $($pIE.AutoConfigURL)" }
    if (Esiste 'Get-DnsClientServerAddress') {
        $dns = Leggi { Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } } "Server DNS"
        if ($null -ne $dns) {
            foreach ($d in $dns) { Nota "   DNS su '$($d.InterfaceAlias)': $($d.ServerAddresses -join ', ')" }
            Nota "Se non riconosci un indirizzo DNS, verificalo: e' un modo per dirottare i siti."
        }
    } else { NonDisponibile "Lettura DNS non disponibile" }
}

function C_Connessioni {
    $tutte = Leggi { Get-NetTCPConnection -State Established } "Connessioni di rete"
    if ($null -ne $tutte) {
        $conn = @($tutte | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|fe80)' })
        $anomale = 0
        if ($conn.Count -gt 0) {
            Nota "Connessioni verso l'esterno attive: $($conn.Count)"
            foreach ($g in ($conn | Group-Object OwningProcess)) {
                $pr = Get-Process -Id $g.Name -ErrorAction SilentlyContinue
                $nome = "PID $($g.Name)"
                if ($pr) { $nome = $pr.ProcessName }
                $ips = $g.Group | Select-Object -First 3 -ExpandProperty RemoteAddress | Sort-Object -Unique
                # In Lampo niente risoluzione dei nomi: fino a 700 ms per indirizzo.
                if ($script:lampo) { $dest = ($ips -join ', ') }
                else { $dest = (($ips | ForEach-Object { NomeHost $_ }) -join ', ') }
                $q = "`"$($pr.Path)`""
                if ($pr -and $pr.Path -and (EsuPercorsoSospetto $q) -and -not (FirmaValida $q) -and -not (GiaRiconosciuto $q "$nome -> $dest")) {
                    $anomale++
                    $prop = ProprietarioDi $q
                    if ($prop) { $t = "$nome (non firmato, parte di '$prop') collegato a $dest  [SHA256 $(Impronta $q)]"; Attenzione $t; $liv = 1; $d = "probabilmente parte di '$prop', collegato a internet" }
                    else { $t = "$nome (non firmato, da cartella anomala) collegato a $dest  [SHA256 $(Impronta $q)]"; Allarme $t; $liv = 2; $d = "collegato a internet, non appartiene a nessun programma installato" }
                    if ((StatoConferma $q) -ne 'no') { ProponiFile $q $d $liv $t }
                } elseif (-not ($pr -and $pr.Path -and (QuandoConfermato $q))) { Nota "   $nome -> $dest" }
            }
        } else { Nota "Nessuna connessione esterna attiva in questo momento" }
        if ($anomale -eq 0) { Ok "Nessun programma non firmato da cartelle anomale collegato a internet" }
    }
    if (Esiste 'Get-LocalUser') {
        $utenti = Leggi { Get-LocalUser | Where-Object { $_.Enabled } | Select-Object -ExpandProperty Name } "Account locali"
        if ($null -ne $utenti) { Nota "Account attivi: $($utenti -join ', ')" }
        $adm = Leggi { (Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544').Name).Name } "Membri del gruppo Amministratori"
        if ($null -ne $adm) { Nota "Amministratori: $($adm -join ', ')" }
        Nota "Se vedi un account che non hai creato tu, e' un problema serio."
    } else { NonDisponibile "Elenco account non disponibile su questo sistema" }
}

# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAF5nfL+241PIhc
# R1R8pYLCm7JrdA4DAt92OZ3g3Cl1N6CCBCowggQmMIICjqADAgECAhBsFNOb1/0T
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD4ltELYPgsOegJ
# SXpd23y9h0cjl0/lIY0tZGSLCnKhZTANBgkqhkiG9w0BAQEFAASCAYAwC2akgOD1
# d5bPGS83Tz+dDYyXQU7R+NbUUQ7ZwI7DisBd68Pkv4J7k0yYvbcwz1hf/o/EHLNg
# V0WoUGZa7/Ut6e5FV0s+Pe5HeniH8RekBN3YbXClH9rC8LpZgelWjHKfglxNQptw
# WWbeAth6u+zrp3uBNJ7PTdiVU3Y4rLaMK0DwIEUEhGf2fouTCHHbUKtryXMW3+O1
# taJzW9zk1hu7+NyH0Ma+3mIQWe4+m8gZAs0+J8JDKUDakQAD5aXjGR5mGAJVoSvE
# LkWes2Z64UD89UN+wU5D3oZjZGeIMEhv7Q8qnvmNn/BNQ5Q1e9tG0GzCosjPYnH5
# o79PIWYDCzU/Cb9i6MMVZJ/IZgCiVRQ/wVSY0JEQI7aDqltaTiWgx9qFG4bSsCb9
# Y2q5tdctc94Sikzd8TpjI6n69hx5vXAJgMnpHRgP/a4BkV54LhWdiAqrWzD5Iy7e
# 184eBwf/ccmpFus+M8++pvXtpO08NfuWkbDS/DFrmqOlU/lnfe52dBM=
# SIG # End signature block
