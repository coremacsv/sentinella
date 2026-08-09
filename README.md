<img src="sentinella.png" width="130" align="right" alt="Logo di Sentinella: uno scudo con un occhio">

# Sentinella

**Sicurezza e salute del tuo PC. Doppio clic, scegli, leggi il verdetto.**

![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=flat-square&logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?style=flat-square&logo=powershell&logoColor=white)
![Licenza](https://img.shields.io/badge/licenza-MIT-3fb950?style=flat-square)
![Versione](https://img.shields.io/badge/versione-2.0-58a6ff?style=flat-square)

24 controlli che rispondono a due domande: *il mio PC è infetto?* e *il mio PC sta bene?*
Nessuna installazione, nessun account, niente che esca dal tuo computer.

```
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗      █████╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██║     ██╔══██╗
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ██║     ███████║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██║     ██╔══██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗███████╗██║  ██║
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
                                                                      ~ by lozy ~

  [ sicurezza e salute del tuo PC ]  v2.0
```

---

## Perché esiste

È nato da un'infezione vera: un finto *mod menu* per un videogioco, scaricato **alle 3:38 di notte**, che in pochi secondi ha copiato password del browser, cookie di sessione e token di accesso, e li ha spediti a chi l'aveva confezionato.

Da lì il nome: una sentinella è quella che veglia mentre gli altri dormono.

Due lezioni di quella notte sono diventate le due caratteristiche che distinguono Sentinella da un normale antivirus:

> **L'antivirus non aveva rilevato nulla.** Né prima né dopo. Quei malware vengono ri-impacchettati di continuo proprio per non farsi riconoscere dalle firme. Per questo Sentinella non si limita a chiedere all'antivirus: va a guardare dove i malware si nascondono davvero — esclusioni aggiunte all'antivirus, avvii automatici, chiavi di registro poco note, attività pianificate, persistenza WMI, estensioni del browser, proxy e DNS dirottati.

> **La formattazione aveva pulito solo `C:`.** Il file infetto era sopravvissuto su un secondo disco, e la scansione rapida di Windows non ci guarda nemmeno. Qui **entrambe le modalità esaminano tutti i dischi**.

---

## Non è un antivirus

| | Defender / Malwarebytes | Sentinella |
|---|---|---|
| Riconosce un virus nei file | ✅ motore proprio | ➖ si appoggia a Defender |
| Protezione in tempo reale | ✅ | ❌ |
| Rimuove e mette in quarantena | ✅ | ❌ non tocca niente |
| Dice se l'antivirus è stato sabotato | ❌ | ✅ |
| Mostra avvii automatici e persistenza | ❌ | ✅ |
| Controlla proxy, DNS, file hosts | ❌ | ✅ |
| Estensioni del browser | ❌ | ✅ |
| Salute del PC (dischi, crash, driver) | ❌ | ✅ |
| Dice cosa è **cambiato** dall'ultima volta | ❌ | ✅ |

**In una riga: loro guardano i file, Sentinella guarda il computer.**

Usali insieme: Defender sempre acceso, Sentinella quando vuoi sapere se qualcuno ha messo le mani nel sistema.

---

## Come si usa

1. Scarica i file e mettili nella stessa cartella
2. Doppio clic su **`SENTINELLA.bat`**
3. Conferma la richiesta di permessi di amministratore
4. Scegli **1** (rapida) o **2** (completa)

Il report compare **a schermo**: verdetto in evidenza, quadro di tutti i 24 controlli uno per uno, poi il dettaglio. Alla fine Sentinella chiede se vuoi una copia — in **testo** o in **pagina web** — e se dici no non lascia niente sul disco.

> **Vuoi l'icona sul Desktop?** Doppio clic su `Crea-collegamento.bat`.

### Le due modalità

|  | Rapida | Completa |
|---|---|---|
| Durata | ~5 minuti | 30 minuti - qualche ora |
| I 24 controlli | ✅ tutti | ✅ tutti |
| Dischi esaminati | **tutti** | **tutti** |
| Antivirus | memoria, punti di avvio e i file a rischio aggiunti negli ultimi 45 giorni, su ogni disco | ogni singolo file di ogni disco |
| Integrità file di sistema | ➖ | ✅ |
| Storico errori | 7 giorni | 30 giorni |

Cambia **quanto a fondo** si guarda, non *dove*.

---

## I 24 controlli

### 🛡️ Sicurezza
| | |
|---|---|
| Antivirus | stato, protezione in tempo reale, età delle definizioni, protezione da manomissione |
| **Esclusioni antivirus** | cartelle che l'antivirus è stato istruito a ignorare — primo trucco degli infostealer |
| Storico minacce | rilevamenti passati e se sono stati risolti |
| Firewall | stato dei tre profili |
| Avvio automatico | registro e cartella Esecuzione automatica |
| **Nascondigli avanzati** | Winlogon `Shell` e `Userinit`, `AppInit_DLLs`, dirottamenti IFEO, componenti agganciati a Explorer |
| Attività pianificate | quelle che eseguono file da cartelle utente o temporanee |
| Processi | in esecuzione da cartelle anomale, con impronta SHA256 |
| Servizi e WMI | servizi non firmati e sottoscrizioni WMI |
| **Estensioni del browser** | Chrome, Edge, Brave, Vivaldi, Opera e Firefox — quelle aggiunte di recente vengono segnalate |
| **Rete** | file hosts, proxy, DNS: i tre modi per dirottare il traffico |
| Connessioni | verso l'esterno, **con il nome del sito** e il programma che le ha aperte |
| Account | utenti attivi e amministratori |

### 💚 Salute
| | |
|---|---|
| Dischi | spazio libero e **stato SMART**: errori non corretti, usura SSD, temperatura, ore di accensione |
| Memoria | uso complessivo e processi più pesanti |
| **Errori di sistema** | eventi critici, spegnimenti anomali, schermate blu, errori di disco |
| Crash | file di dump delle schermate blu |
| Driver | periferiche in errore |
| Aggiornamenti | ultimo installato e riavvii in sospeso |
| Programmi recenti | installati negli ultimi 30 giorni |
| Integrità sistema | `sfc /verifyonly` (solo completa) |

### 🕓 Confronto
| | |
|---|---|
| **Novità dall'ultima scansione** | Sentinella ricorda avvii, attività, servizi, account, DNS, hosts, esclusioni e programmi. Al controllo successivo ti dice **cosa è cambiato** |

Quest'ultimo è il più potente: una fotografia dice se qualcosa *sembra* strano, due fotografie dicono cosa è *cambiato*. Un'esclusione antivirus comparsa ieri pesa molto più della stessa vista una volta sola.

**Ogni sospetto passa dalla firma digitale prima di diventare un allarme.** Senza questo controllo uno strumento del genere finisce per accusare Windows Defender stesso di essere un malware, perché vive in una cartella "sospetta".

---

## Cosa NON fa

Onestà, prima di tutto:

- **Non rimuove niente.** Diagnostica, non cura. Nessun file cancellato, nessuna impostazione cambiata.
- **Non è un antivirus.** Si appoggia a Windows Defender per l'esame dei file.
- **Non garantisce che il PC sia pulito.** Controlla i nascondigli più comuni, non tutti. Un malware appena confezionato può non essere riconosciuto da nessuna firma — è esattamente com'è nata questa storia.
- **Non manda niente da nessuna parte.** Nessuna connessione, nessuna telemetria: i report restano sul tuo computer.

Un esito pulito rende un problema **molto improbabile**, non impossibile. Il buon senso su cosa scarichi resta l'ultima difesa.

---

## Perché non è un `.exe`

**Di proposito.** Un eseguibile non firmato che analizza il sistema fa scattare gli avvisi di Windows — pessimo biglietto da visita per uno strumento di sicurezza — e soprattutto nasconde ciò che fa.

Qui il codice è un file di testo: puoi aprirlo e **leggerlo riga per riga prima di eseguirlo**. Per un programma a cui dai i permessi di amministratore, è il minimo che dovresti pretendere.

---

## Requisiti

- Windows 10 o 11
- PowerShell 5.1 (già incluso in Windows)
- Permessi di amministratore (il `.bat` li chiede da solo)

Funziona anche senza permessi, ma alcuni controlli restano parziali e Sentinella lo dice chiaramente. Se manca Windows Defender (perché usi un altro antivirus), i controlli che dipendono da lui vengono saltati con un avviso: tutto il resto funziona lo stesso.

---

## File

| | |
|---|---|
| `SENTINELLA.bat` | avvio: chiede i permessi e lancia il programma |
| `sentinella.ps1` | il programma, in chiaro e leggibile |
| `Crea-collegamento.bat` | crea sul Desktop un collegamento con l'icona |
| `sentinella.ico` · `sentinella.png` | il logo |

L'impronta per il confronto tra scansioni viene salvata in `%LOCALAPPDATA%\Sentinella\`.

---

## Licenza

MIT — usalo, modificalo, distribuiscilo.

---

<div align="center">
  <sub>Sentinella — <b>by lozy</b></sub>
</div>
