# Sentinella

```
    \  /    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗      █████╗
   ██████   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██║     ██╔══██╗
  ████████  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ██║     ███████║
  ████████  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██║     ██╔══██║
  ████████  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗███████╗██║  ██║
     vv     ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
                                                                             ~ by lozy ~
```

Diagnosi di sicurezza e salute per Windows. Doppio clic, scegli quanto a fondo, leggi il verdetto.

Non è un antivirus: non rimuove niente, non protegge in tempo reale. Guarda se il sistema è stato manomesso — esclusioni antivirus, avvii automatici, Winlogon, IFEO, attività pianificate, estensioni del browser, proxy, DNS, file hosts — cerca le tracce lasciate dagli infostealer (comandi incollati da finti CAPTCHA, programmi scaricati e avviati, Discord manomesso) e come sta il PC (dischi, SMART, memoria, crash, errori hardware, driver). Poi ricorda cosa ha trovato, e alla scansione successiva ti dice cosa è cambiato. Per ogni cosa che trova, spiega cosa significa e dove andare a sistemarla — pensato per chi non mastica informatica, non solo per chi già sa cosa cercare.

Nato dopo un'infezione vera: un finto mod menu scaricato alle 3:38 di notte, invisibile a Defender sia prima che dopo, sopravvissuto a una formattazione perché stava su un secondo disco che nessuno aveva guardato. Sentinella controlla proprio i punti che quella notte sono stati saltati — ed esamina sempre tutti i dischi, in tutte e tre le modalità.

## Uso

```
1. scarica i file nella stessa cartella
2. doppio clic su SENTINELLA.bat
3. concedi i permessi di amministratore
4. scegli: 1 lampo (<1 min) · 2 rapida (~5 min) · 3 completa (30 min - ore)
```

`Crea-collegamento.bat` mette l'icona sul Desktop. Serve tutta la cartella: `sentinella.ps1` carica i file della sottocartella `moduli`.

Il report esce a schermo — verdetto, quadro dei controlli, e per ogni allarme una spiegazione in italiano semplice più l'azione concreta da fare. Alla fine puoi salvarlo in `.txt`, `.html`, `.json` o in tutti e tre: finisce in `Desktop\Sentinella-Report\`, una sottocartella per tipo. Una copia JSON di ogni scansione resta comunque in `%LOCALAPPDATA%\Sentinella\storico` (le ultime 50).

## Mai "OK" senza aver guardato

Ogni controllo ha cinque esiti possibili: `[ OK ]` a posto, `[ !! ]` da guardare, `[ XX ]` grave, `[ -- ]` non applicabile, e `[ ?? ]` **non verificato**. Un controllo è OK solo se lo dichiara esplicitamente; se una lettura fallisce (permessi, servizio spento, errore di Windows) o il controllo si interrompe, risulta non verificato — e il verdetto finale non può essere "tutto regolare". Esempio reale: senza permessi di amministratore la chiave IFEO non è leggibile, e la v2 rispondeva comunque "nessun dirottamento IFEO".

## Tre modalità

**Lampo** (<1 minuto, nessuna scansione antivirus) — 16 controlli: esclusioni antivirus, avvio automatico, Winlogon/IFEO, attività pianificate, servizi, rete, account, tracce da infostealer, e cosa è cambiato dall'ultima volta.

**Rapida** (~5 minuti) — tutti i 30 controlli, antivirus su memoria/avvio/file a rischio recenti su ogni disco.

**Completa** (30 min - ore) — come la rapida, ma l'antivirus apre ogni file di ogni disco, più verifica dei file di sistema. Alla fine propone la scansione offline di Defender (riavvia il PC: parte solo se scrivi `RIAVVIA`).

## 30 controlli

**Sicurezza** — integrità di Sentinella stessa, antivirus e sue esclusioni, storico minacce, firewall, avvio automatico, Winlogon/AppInit/IFEO, attività pianificate, processi, servizi, persistenza WMI, estensioni browser, proxy/DNS/hosts, connessioni con nome host, account e amministratori

**Tracce da infostealer** — comandi incollati in Win+R, Esplora file e PowerShell (trucco ClickFix/FileFix dei finti CAPTCHA); eseguibili e script scaricati di recente con il sito di provenienza; programmi avviati da Download/Desktop/cartelle temporanee anche se poi cancellati (registro BAM di Windows); Discord con il file di avvio manomesso (ladri di account)

**Salute** — spazio disco, SMART, memoria, errori critici, errori hardware WHEA collegati ai riavvii con diagnosi per core del processore, blocchi della scheda video, crash/BSOD, periferiche con spiegazione del codice d'errore, aggiornamenti, programmi installati di recente, integrità file di sistema

**Confronto** — impronta del sistema salvata a ogni scansione; alla successiva, cosa è nuovo e cosa è sparito

## Meno falsi allarmi

Un file che parte da solo senza firma digitale non è automaticamente rosso:
- se risulta parte di un programma installato (sta nella sua cartella **e** i dati interni del file citano quel programma) è giallo;
- se Sentinella ti chiede "lo riconosci?" e rispondi sì, la risposta è legata all'**impronta SHA256** del file: se il file cambia anche di un byte, l'allarme torna.

## Uso da riga di comando

```
powershell -ExecutionPolicy Bypass -File sentinella.ps1 -Modo Lampo -Silenzioso
```

Nessuna domanda, nessun output a schermo oltre a una riga di riepilogo, report JSON nello storico. Codice di uscita: `0` tutto regolare, `1` da guardare, `2` grave, `3` nessun problema ma controlli non verificati. Adatto a un'attività pianificata.

## Integrità e firma

I file `.ps1` sono firmati digitalmente dall'autore. A ogni scansione Sentinella verifica le proprie firme: se un file è stato modificato dopo la firma, lo segnala in rosso. Limite onesto: ferma modifiche accidentali e malware generici, non un attacco costruito apposta contro Sentinella. Chi modifica il codice rifirma con `strumenti\Firma-Sentinella.ps1` (crea un certificato personale con chiave non esportabile; non tocca le autorità attendibili di Windows).

## Test

La logica che decide cosa è sospetto sta in `moduli\Analisi.ps1` ed è provata con dati finti in `test\`:

```
powershell -ExecutionPolicy Bypass -Command "Invoke-Pester .\test"
```

Scritti per Pester 3.4, incluso in Windows 10/11: niente da installare.

## Struttura

```
SENTINELLA.bat          avvio con permessi di amministratore
sentinella.ps1          menu, elenco dei controlli, report
moduli\Base.ps1         motore dei controlli ("mai OK senza aver guardato")
moduli\Analisi.ps1      logica di giudizio, senza effetti sul sistema (testata)
moduli\Sistema.ps1      firme, programmi installati, conferme
moduli\Integrita.ps1    verifica della firma di Sentinella
moduli\Sicurezza.ps1    parte A
moduli\Infostealer.ps1  parte B
moduli\Salute.ps1       parte C
moduli\Antivirus.ps1    parte D
moduli\Confronto.ps1    parte E
moduli\Report.ps1       schermo, testo, pagina web, JSON
strumenti\              firma del codice (per l'autore)
test\                   test automatici
```

## Perché non è un `.exe`

Un eseguibile non firmato che analizza il sistema fa scattare gli avvisi di Windows e nasconde cosa fa. Qui il codice è un file di testo: leggibile riga per riga prima di eseguirlo, con i permessi di amministratore che gli dai.

## Limiti

Controlla i nascondigli e i guasti più comuni, non tutti. Non rileva file infetti da solo — chiama Defender, che può non riconoscere un malware appena confezionato (è successo). Un esito pulito riduce il rischio, non lo azzera.

## Requisiti

Windows 10/11, PowerShell 5.1 (incluso), permessi di amministratore per l'esame completo.

---

MIT · by lozy
