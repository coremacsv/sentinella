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

Non è un antivirus: non rimuove niente, non protegge in tempo reale. Guarda se il sistema è stato manomesso — esclusioni antivirus, avvii automatici, Winlogon, IFEO, attività pianificate, estensioni del browser, proxy, DNS, file hosts — e come sta il PC (dischi, SMART, memoria, crash, driver). Poi ricorda cosa ha trovato, e alla scansione successiva ti dice cosa è cambiato. Per ogni cosa che trova, spiega cosa significa e dove andare a sistemarla — pensato per chi non mastica informatica, non solo per chi già sa cosa cercare.

Nato dopo un'infezione vera: un finto mod menu scaricato alle 3:38 di notte, invisibile a Defender sia prima che dopo, sopravvissuto a una formattazione perché stava su un secondo disco che nessuno aveva guardato. Sentinella controlla proprio i punti che quella notte sono stati saltati — ed esamina sempre tutti i dischi, in tutte e tre le modalità.

## Uso

```
1. scarica i file nella stessa cartella
2. doppio clic su SENTINELLA.bat
3. concedi i permessi di amministratore
4. scegli: 1 lampo (~15 sec) · 2 rapida (~5 min) · 3 completa (30 min - ore)
```

`Crea-collegamento.bat` mette l'icona sul Desktop.

Il report esce a schermo — verdetto, quadro dei controlli, e per ogni allarme una spiegazione in italiano semplice più l'azione concreta da fare. Alla fine puoi salvarlo in `.txt`, in `.html`, entrambi, o niente.

## Tre modalità

**Lampo** (~15 secondi, nessuna scansione antivirus) — i 12 segnali più gravi: esclusioni antivirus, avvio automatico, Winlogon/IFEO, attività pianificate, servizi, rete, account, e cosa è cambiato dall'ultima volta. Il controllo da fare ogni volta che accendi il PC.

**Rapida** (~5 minuti) — tutti i 24 controlli, antivirus su memoria/avvio/file a rischio recenti su ogni disco.

**Completa** (30 min - ore) — come la rapida, ma l'antivirus apre ogni file di ogni disco, più verifica dei file di sistema.

## 24 controlli

**Sicurezza** — antivirus e sue esclusioni, storico minacce, firewall, avvio automatico, Winlogon/AppInit/IFEO, attività pianificate, processi, servizi, persistenza WMI, estensioni browser, proxy/DNS/hosts, connessioni con nome host, account e amministratori

**Salute** — spazio disco, SMART, memoria, errori critici, crash/BSOD, driver, aggiornamenti, programmi installati di recente, integrità file di sistema

**Confronto** — impronta del sistema salvata a ogni scansione; alla successiva, cosa è nuovo e cosa è sparito

File non firmati vengono marcati solo dopo il controllo della firma digitale — altrimenti lo strumento finisce per accusare Windows Defender stesso, che vive sotto `C:\ProgramData`.

## Perché non è un `.exe`

Un eseguibile non firmato che analizza il sistema fa scattare gli avvisi di Windows e nasconde cosa fa. Qui il codice è un file di testo: leggibile riga per riga prima di eseguirlo, con i permessi di amministratore che gli dai.

## Limiti

Controlla i nascondigli e i guasti più comuni, non tutti. Non rileva file infetti da solo — chiama Defender, che può non riconoscere un malware appena confezionato (è successo). Un esito pulito riduce il rischio, non lo azzera.

## Requisiti

Windows 10/11, PowerShell 5.1 (incluso), permessi di amministratore per l'esame completo.

---

MIT · by lozy
