# AuditTopology – plan, architektura i cele

Ten dokument podsumowuje obecny stan projektu, problemy, decyzje architektoniczne, cele oraz plan dalszych prac. Ma umożliwić sprawne wznowienie pracy w nowej sesji i szybkie zrozumienie aplikacji.

## 1. Opis aplikacji

AuditTopology to narzędzie do półautomatycznego budowania topologii sieci L2/L3 na podstawie danych z urządzeń (SNMP: LLDP/IF/BRIDGE/Q-BRIDGE, w kolejnych krokach CDP; oraz źródeł pośrednich: ARP/route). Narzędzie generuje graf urządzeń i łączy z oceną pewności (confidence) i zapewnia panel diagnostyczny z „dowodami” (evidence), które wyjaśniają na jakiej podstawie dany link został narysowany.

- Backend: Go (serwer HTTP + skaner SNMP)
- UI: statyczna strona (HTML/JS), render grafu (Cytoscape + ELK layout), panel diagnostyczny, eksporty
- Repozutorium kodu (najważniejsze ścieżki):
  - `cmd/auditopology/` – serwer, statyczne UI (embed)
    - `main.go` – punkty końcowe API, serwowanie UI
    - `web/index.html` – interfejs użytkownika
    - `api_types.go` – modele API (ScanRequest/ScanResponse)
  - `internal/collectors/snmp/`
    - `snmp.go` – interfejs i NoOp
    - `gosnmp_collector.go` – realny skaner SNMP (LLDP + IF + FDB/VLAN korelacja)
  - `internal/graph/model.go` – model wewnętrzny topologii
  - `internal/pipeline/pipeline.go` – mapowanie topologii wewnętrznej na format UI

Stan na teraz:
- SNMP (v2c/v3) działa, pobiera:
  - System: sysName/sysDescr (identyfikacja urządzenia)
  - IF-MIB: ifName/ifDescr (nazwy interfejsów)
  - LLDP: remote/local (jeżeli włączony) → krawędzie high confidence z Evidence
  - CDP: CISCO-CDP-MIB (sąsiedzi) → krawędzie high confidence z Evidence + raw dump (debug)
  - Q-BRIDGE-MIB: dot1qTpFdbPort (FDB), korelacja VLAN+MAC między urządzeniami → krawędzie medium confidence z Evidence
- Diagnostyka (backend → API → merge do project.json):
  - Per-device Evidence: lldpLocalCount, lldpRemoteCount, fdbTotalEntries, vlanCount, oidErrors (rejestrowane błędy OID)
  - Per-edge Evidence: source (lldp/cdp/fdb), confidence, A/B {device, if}, vlan (dla fdb), sharedMacs, sampleMacs<=5, usedOids[]
  - Diagnostics.Devices/Edges w odpowiedzi /api/scan są uzupełniane na podstawie Evidence
- Workdir i trwałość:
  - Zapisy skanu: scans/YYYY-MM-DD_hhmmss/topo.json, diag.json
  - Inkrementalny cache + historia: project/project.json (merge urządzeń/krawędzi z licznikami lastSeen/seenCount)
- UI:
  - Parametry skanu: seedy (parsing: newline/`,`/`;`/spacje), SNMP (v2c/v3)
  - Widok grafu i eksport (PNG/SVG/PDF)
  - Panel „Diagnostyka” – UI gotowe, teraz zasilane rzeczywistym Evidence po stronie API

## 2. Cel główny

Jak najrzetelniejsze odtworzenie topologii (fizyczna/logiczną L2) z jasnym wskazaniem podstaw dowodowych:
- High confidence: LLDP/CDP (z nazwami portów)
- Medium confidence: korelacja FDB + VLAN (wspólne MAC w danym VLAN)
- Low confidence: ewentualne heurystyki (w późniejszych iteracjach)

Każda krawędź ma posiadać „evidence” opisujące źródło, parametry, statystyki i OID-y.

## 3. Kluczowe problemy i aktualne ograniczenia

- LLDP bywa wyłączone lub ograniczone – sam LLDP nie wystarczy w audytach.
- Różnice vendorowe – konieczność wspierania CDP i rozszerzeń LLDP/LLDP-MED; różna prezentacja ifName/ifDescr.
- FDB/VLAN korelacja może dawać false-positive przy małej liczbie hostów; potrzebny próg i diagnostyka (sharedMacs, sample MAC-y).
- Brak pełnych „evidence” w API/diagnostyce – w toku wdrożenia.
- Brak bazy/cache urządzeń i autodiscovery – w toku wdrożenia.
- Brak warstwowego workdir (folder roboczy) – w toku wdrożenia.

## 4. Decyzje i założenia

- Warstwy dowodowe:
  - High: LLDP/CDP – traktowane jako najbardziej wiarygodne (faktyczna sąsiedniość portów)
  - Medium: FDB/VLAN – dobra korelacja logiczna, wymaga progu i widoczności hostów
- Konfiguracja progu FDB (domyślnie 3 wspólne MAC-y), możliwość zmiany w UI
- Zasada jawnego raportowania dowodów: UI panel Diagnostyka + eksport JSON/CSV
- Praca „bezpieczna” w audycie:
  - Bind rozmiaru skanu (limity współbieżności, white/blacklist CIDR)
  - Read-only SNMP, brak prób modyfikacji

## 5. API – obecny zakres

- GET `/api/topology` – NoOp (przykładowy graf do podglądu)
- GET `/api/workdir` – zwraca aktualną ścieżkę workdir
- POST `/api/workdir` – ustawia ścieżkę workdir i tworzy strukturę
- GET `/api/project` – zwraca bieżący stan projektu po merge (project.json)
- POST `/api/scan` – realny skan
  - Request (MVP):
    ```
    {
      "seeds": ["10.0.0.1", "10.0.0.2"],
      "snmpVersion": "v2c" | "v3",
      "community": "public",
      "v3user": "",
      "v3authproto": "",
      "v3authpass": "",
      "v3privproto": "",
      "v3privpass": "",
      "fdbThreshold": 3
    }
    ```
  - Response (MVP):
    ```
    {
      "status": "ok" | "error",
      "topology": {
        "nodes": [
          {
            "id": "deviceId",
            "label": "SYSNAME",
            "vendor": "cisco|aruba|...",
            "evidence": {
              "lldpLocalCount": 12,
              "lldpRemoteCount": 8,
              "mgmtIPs": ["10.0.0.1"],
              "fdbTotalEntries": 1234,
              "vlanCount": 10,
              "oidErrors": ["walk dot1qTpFdbPort error: ..."]
            }
          }
        ],
        "edges": [
          {
            "id": "devA:Gi1/0/1-devB:Gi0/1",
            "source": "devA",
            "target": "devB",
            "score": "high|medium|low",
            "evidence": {
              "source": "lldp|cdp|fdb",
              "confidence": "high|medium|low",
              "a": {"device":"devA","if":"Gi1/0/1"},
              "b": {"device":"devB","if":"Gi0/1"},
              "vlan": 10,
              "sharedMacs": 5,
              "sampleMacs": ["aa:bb:..."],
              "usedOids": ["..."]
            }
          }
        ]
      },
      "diagnostics": {
        "stats": { "nodes": n, "edges": m, "source": ["lldp","fdb","cdp"] },
        "devices": { "deviceId": { /* jak nodes[].evidence */ } },
        "edges": { "edgeId": { /* jak edges[].evidence */ } },
        "raw": { "cdp": { "OID": "value", "...": "..." } }
      },
      "error": ""
    }
    ```
  - Uwaga: diagnostics zawiera mapy devices/edges z Evidence i surowe zrzuty (np. raw.cdp).

## 6. Workdir (folder roboczy) – zachowanie

Wymaganie: baza/artefakty nie mogą być bundlowane z aplikacją; wszystko zapisujemy w zewnętrznym folderze roboczym.

- Domyślna lokalizacja:
  - Windows: `%LOCALAPPDATA%\AuditTopology\workspace`
  - Linux: `$HOME/.local/share/AuditTopology/workspace`
  - macOS: `~/Library/Application Support/AuditTopology/workspace`
- Konfiguracja:
  - Priorytet: ENV `AUDITOP_WORKDIR` → `config.json` w profilu użytkownika → domyślna ścieżka OS
  - Plik `config.json` (per-user): Windows `%LOCALAPPDATA%\AuditTopology\config.json`, Linux `~/.config/AuditTopology/config.json`, macOS `~/Library/Preferences/AuditTopology/config.json`
- Struktura:
  ```
  workspace/
    scans/
      YYYY-MM-DD_hhmmss/
        topo.json
        diag.json
    project/
      project.json        # stan po merge (inkrementalny cache + historia)
    cache/
    artifacts/
  ```
- API:
  - GET `/api/workdir` → { "path": "…" }
  - POST `/api/workdir` → { "path": "…" } (ustawia + EnsureStructure)
  - GET `/api/project` → zwraca stan projektu (project.json)
- UI (mini, do uzupełnienia):
  - Pokazanie aktualnego workdir i zmiana (prompt), „Zapisano do: …/scans/…/topo.json” po skanie

## 7. Plan wdrożenia – kolejność kroków (aktualizacja)

A. Workdir + sesje skanu (WDROŻONE)
- [x] internal/storage/workdir:
  - [x] ResolveWorkdir(), EnsureStructure(), NewScanSession(), SaveJSON()
  - [x] project/project.json: LoadProject(), SaveProject(), MergeProject() (inkrementalny cache + historia: lastSeen/seenCount, upsert nodes/edges)
- [x] API:
  - [x] GET/POST `/api/workdir`
  - [x] GET `/api/project`
  - [x] `/api/scan`: zapis `topo.json` i `diag.json` + merge do `project.json`
- [x] UI:
  - [x] Sekcja „Ustawienia” (minimalna) + informacja o ścieżce zapisu w Diagnostyce

B. Diagnostyka – realne „evidence” (Etap bieżący, CZĘŚCIOWO WDROŻONE)
- [x] internal/collectors/snmp/gosnmp_collector.go:
  - [x] Per-device: `lldp.localCount/remoteCount`, `fdb.totalEntries`, `vlanCount`, `oidErrors` (część)
  - [x] Per-edge: `source (lldp/cdp/fdb)`, `confidence`, `a:{device,if}`, `b:{device,if}`, `vlan (fdb)`, `sharedMacs`, `sampleMacs[<=5]`, `usedOids[]`
- [x] internal/pipeline/pipeline.go:
  - [x] Przekazanie evidence do UI Topology oraz dalej do `ScanResponse.Diagnostics`
- [x] API `/api/scan`:
  - [x] Uzupełnianie `Diagnostics.Devices/Edges` na podstawie evidence w TopologyPayload
- [x] Rozszerzenia (następne iteracje):
  - [x] Per-device: `MgmtIPs` z LLDP mgmtAddress (best‑effort, różne indeksacje vendorowe)
  - [ ] `OidErrors` dla LLDP/IF/CDP (obecnie FDB)
  - [ ] Debug raw: profile LLDP/IF/FDB w `/api/debug/snmpwalk`

C. Ulepszenie skanera (rzetelność topologii)
- [x] CDP (finalizacja i testy na różnych platformach) – obecnie działa podstawowo
- [x] IP w grafie:
  - [x] nodes.data.mgmtIPs + toggle „Pokaż IP pod nazwą” (UI)
- [ ] Autodiscovery v1 (kontrolowany zasięg):
  - [ ] Seeds: IP/FQDN/CIDR
  - [ ] Z seedów: ARP/route/LLDP mgmtAddress → pula IP do krótkich przebiegów (limity maxDepth, maxHosts)
  - [ ] Whitelist/blacklist CIDR, limity równoległości

D. Cache urządzeń (poza binarką)
- [ ] `internal/storage/cache` (BoltDB lub SQLite):
  - [ ] Tabele devices (metadata: sysName, mgmtIPs, vendor, role, ifMap, LLDP/FDB stats, updatedAt)
  - [ ] Retencja: ostatnie N/ostatnie 30 dni
  - [ ] Eksport/Import JSON na żądanie

C. Ulepszenie skanera (rzetelność topologii)
- [ ] CDP (CISCO-CDP-MIB) – linki high confidence (z remote device/port)
- [ ] IP w grafie:
  - [ ] nodes.data.mgmtIPs + toggle „Pokaż IP pod nazwą”
- [ ] Autodiscovery v1 (kontrolowany zasięg):
  - [ ] Seeds: IP/FQDN/CIDR
  - [ ] Z seedów: ARP (ipNetToMedia/arpTable), routes (ipRouteTable/ipCidrRouteTable), LLDP mgmtAddress → nowa pula IP do krótkich przebiegów (limit maxDepth, maxHosts)
  - [ ] Whitelist/blacklist CIDR, limity równoległości

D. Cache urządzeń (poza binarką)
- [ ] `internal/storage/cache` (BoltDB lub SQLite):
  - [ ] Tabele/wiadra: devices (metadata: sysName, mgmtIPs, vendor, role, ifMap, LLDP/FDB stats, updatedAt)
  - [ ] Retencja: ostatnie N/ostatnie 30 dni
  - [ ] Eksport/Import JSON na żądanie

## 8. Alternatywy i decyzje do potwierdzenia

- Baza: BoltDB (prosty plik, zero-deps) vs SQLite (potężniejsza kwerenda). Start: BoltDB, później możliwy switch.
- Prezentacja IP na węzłach: stały dopisek pod label vs toggle. Decyzja: toggle (domyślnie off).
- Próg FDB: domyślne 3, w małych sieciach 2. UI zawiera suwak/selector.
- CDP w środowiskach nie-Cisco: niektóre Netgeary/Nadwory mogą wspierać; jeśli brak – pozostajemy przy LLDP + FDB.

## 9. Jak uruchomić aplikację

### Wymagania:
- Go 1.24.4 lub nowszy
- Port 5173 wolny (lub ustaw zmienną PORT)

### Uruchomienie:
```bash
# W głównym katalogu projektu
go run ./cmd/auditopology

# Lub z custom portem
PORT=8080 go run ./cmd/auditopology
```

### Dostęp:
- **URL:** http://localhost:5173 (lub custom port)
- **API:** http://localhost:5173/api/

---

## 10. Instrukcje użytkowania

### 🎛️ **Podstawowe funkcje**

#### **1. Wyświetlanie IP na grafie** ✅
1. Kliknij **"Przeładuj"** (używa NoOp collector z przykładowymi danymi)
2. Zaznacz checkbox **"Pokazuj IP na grafie"**
3. **Rezultat:** IP pod nazwami urządzeń (np. "CORE-1\n(10.0.0.1, 192.168.1.1)")

#### **2. Konfigurowalny próg FDB** ✅
1. W sekcji **"Ustawienia"** znajdź **"Próg FDB (wspólne MAC-y)"**
2. Zmień wartość z 3 na 2 (niższy próg = więcej połączeń FDB)
3. Wykonaj skan rzeczywistych urządzeń
4. **Rezultat:** Przy niższym progu więcej połączeń, przy wyższym pewniejsze

#### **3. Panel Diagnostyka** ✅
1. Po skanie kliknij **"Diagnostyka"**
2. **Tabela Urządzenia:** LLDP counts, FDB entries, VLANy, błędy OID
3. **Tabela Krawędzie:** source (lldp/cdp/fdb), confidence, porty A/B, VLAN, shared MACs
4. **JSON:** pełne dane diagnostyczne z evidence

### 🔍 **Autodiscovery - Automatyczne odkrywanie urządzeń** ✅

#### **Włączenie Autodiscovery:**
1. W sekcji **"🔍 Autodiscovery"** zaznacz **"Włącz automatyczne odkrywanie urządzeń"**
2. Pojawią się dodatkowe opcje konfiguracji

#### **Konfiguracja parametrów:**

**Maksymalna głębokość (hops)** - domyślnie: 2
- **1 hop:** tylko bezpośredni sąsiedzi seeds
- **2 hops:** sąsiedzi + ich sąsiedzi (zalecane)
- **3+ hops:** głębsze skanowanie (ostrożnie!)

**Limit urządzeń** - domyślnie: 50
- Bezpieczny limit aby nie przeciążyć sieci
- Zwiększ dla większych środowisk (max 200)

**Dozwolone sieci (CIDR):**
```
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
```

**Zabronione sieci (CIDR)** - domyślnie:
```
127.0.0.0/8      # localhost
169.254.0.0/16   # link-local
```

#### **Scenariusze testowe:**

**TEST 1: Podstawowe autodiscovery**
```
Seeds: 192.168.1.1 (TYLKO JEDEN IP!)
Autodiscovery: ✅ Enabled
Max Depth: 2, Max Devices: 20
Whitelist: 192.168.1.0/24
Oczekiwane: 5-15 urządzeń zamiast 1
```

**TEST 2: Multi-subnet discovery**
```
Seeds: 192.168.1.1
Max Depth: 2
Whitelist: 192.168.0.0/16, 10.0.0.0/8
Oczekiwane: urządzenia z różnych segmentów
```

> **⚠️ Uwaga:** Autodiscovery wymaga sieci z kilkoma urządzeniami SNMP (routery, switche) aby pokazać swoje możliwości. W małych sieciach domowych może nie znaleźć dodatkowych urządzeń.

#### **Interpretacja wyników:**
Panel Diagnostyka → Autodiscovery pokazuje:
```
• Znalezione urządzenia: 15
• Maksymalna głębokość: 2  
• Czas skanowania: 45.2s
• Oryginalne seeds: 192.168.1.1,192.168.1.10
• Błędy: timeout on 192.168.1.50
```

### 📊 **Workdir i sesje skanowania** ✅
1. W sekcji "Ustawienia" sprawdź **"Folder roboczy (Workdir)"**
2. Opcjonalnie zmień ścieżkę przez **"Zmień"**
3. Po skanie sprawdź komunikat **"Zapisano do: ..."**
4. Pliki zapisane w `workdir/scans/YYYY-MM-DD_hhmmss/`

---

## 11. API Reference

### Podstawowe endpointy:
```bash
# Workdir info
GET /api/workdir

# Project state  
GET /api/project

# Sample topology (NoOp)
GET /api/topology
```

### Skanowanie z pełnymi opcjami:
```bash
POST /api/scan
{
  "seeds": ["192.168.1.1"],
  "snmpVersion": "v2c",
  "community": "public",
  "fdbThreshold": 3,
  "cdpDebug": true,
  
  // Autodiscovery options
  "autodiscoveryEnabled": true,
  "autodiscoveryMaxDepth": 2,
  "autodiscoveryMaxDevices": 50,
  "autodiscoveryWhitelist": ["192.168.0.0/16"],
  "autodiscoveryBlacklist": ["127.0.0.0/8"]
}
```

### Debug SNMP walk:
```bash
POST /api/debug/snmpwalk
{
  "target": "192.168.1.1",
  "community": "public", 
  "version": "v2c",
  "oids": ["1.3.6.1.2.1.1.5.0"]
}
```

## 10. Najważniejsze OID-y (MVP)

- System:
  - sysName.0: `.1.3.6.1.2.1.1.5.0`
  - sysDescr.0: `.1.3.6.1.2.1.1.1.0`
- IF-MIB:
  - ifName: `.1.3.6.1.2.1.31.1.1.1.1`
  - ifDescr: `.1.3.6.1.2.1.2.2.1.2`
- LLDP (IEEE 802.1AB):
  - remote sysName: `.1.0.8802.1.1.2.1.4.1.1.9`
  - remote portId: `.1.0.8802.1.1.2.1.4.1.1.7`
  - remote localPortNum: `.1.0.8802.1.1.2.1.4.1.1.2`
  - local port desc: `.1.0.8802.1.1.2.1.3.7.1.4`
  - (plan) mgmtAddress (lldpRemManAddrTable): `.1.0.8802.1.1.2.1.4.2` (złożone indeksy)
- BRIDGE/Q-BRIDGE:
  - dot1dBasePortIfIndex: `.1.3.6.1.2.1.17.1.4.1.2`
  - dot1qTpFdbPort: `.1.3.6.1.2.1.17.7.1.2.2.1.2` (index: vlan + MAC)
- CDP:
  - CISCO-CDP-MIB: `1.3.6.1.4.1.9.9.23.1.2.1` (neighbors, deviceId, portId, capabilities)
- (Planowane) ARP / Route:
  - arpTable/ipNetToMedia
  - ipRouteTable/ipCidrRouteTable

## 12. Stan wykonania i roadmap

### ✅ **ZAIMPLEMENTOWANE (2025-08-07)**

**Podstawowe funkcje:**
- [x] Endpoint `/api/scan` (SNMP LLDP + IF + FDB korelacja) + Evidence LLDP/CDP/FDB
- [x] Propagacja Evidence: collector → pipeline → API (TopologyPayload + Diagnostics.Devices/Edges)
- [x] Workdir i zapisy artefaktów; project.json z merge (inkrementalny cache + historia)
- [x] Endpointy: `/api/workdir` (GET/POST), `/api/project` (GET), `/api/debug/snmpwalk` (BULKWALK OID)
- [x] UI: formularz skanu + render grafu, eksporty; parsing wielu seedów; panel „Diagnostyka"

**Ulepszenia skanowania:**
- [x] **Wyświetlanie IP na grafie** ✅ DZIAŁA - rozszerzone zbieranie z 4 źródeł (target IP, ipAddrTable, LLDP mgmt)
- [x] **Konfigurowalny próg FDB** ✅ DZIAŁA - suwak 1-10 wspólnych MAC-ów w UI
- [x] **Autodiscovery** ✅ ZAIMPLEMENTOWANE - automatyczne odkrywanie z ARP/routing/LLDP tables
- [x] **Bezpieczne limity** ✅ DZIAŁA - głębokość, liczba urządzeń, CIDR whitelist/blacklist
- [x] **Diagnostyka autodiscovery** ✅ DZIAŁA - statystyki w panelu diagnostycznym

> **📝 Status Autodiscovery:** Funkcjonalność jest w pełni zaimplementowana i gotowa do testów. Wymaga sieci z kilkoma urządzeniami SNMP do demonstracji możliwości. Testowanie w toku.

### 🔄 **W TOKU**
- [ ] Debug profiles w `/api/debug/snmpwalk`: lldp/if/fdb/cdp (predefiniowane listy OID)
- [ ] Pełne OidErrors dla LLDP/IF/CDP (obecnie tylko FDB)

### 📋 **ROADMAP - Następne funkcje**

**PRIORYTET 1: STP Discovery (1-2 dni)**
- [ ] Spanning Tree Protocol analysis
- [ ] Wykrywanie blocked/forwarding ports
- [ ] Identyfikacja root bridge
- [ ] Mapowanie fizycznej vs logicznej topologii

**PRIORYTET 2: LACP/LAG Detection (1-2 dni)**
- [ ] Link Aggregation discovery
- [ ] Grupowanie physical links w logical LAGs
- [ ] Proper bandwidth calculations
- [ ] Redundancy mapping

**PRIORYTET 3: Performance Metrics (2-3 dni)**
- [ ] Interface utilization monitoring
- [ ] Error rates collection
- [ ] Historical data storage
- [ ] Dashboard z real-time stats

**PRIORYTET 4: Multi-vendor Protocols (1-2 dni)**
- [ ] EDP (Extreme Discovery Protocol)
- [ ] FDP (Foundry Discovery Protocol)  
- [ ] NDP (Nortel Discovery Protocol)
- [ ] Unified protocol abstraction

## 13. Wskazówki audytowe

### **Optymalne ustawienia dla różnych środowisk:**

**Małe sieci (< 20 urządzeń):**
- Próg FDB: 2-3 wspólne MAC-y
- Autodiscovery: Max Depth 2, Max Devices 30
- Whitelist: konkretne subnety

**Średnie sieci (20-100 urządzeń):**
- Próg FDB: 3-4 wspólne MAC-y  
- Autodiscovery: Max Depth 2, Max Devices 100
- Blacklist: management networks

**Duże sieci (100+ urządzeń):**
- Próg FDB: 4-5 wspólnych MAC-ów
- Autodiscovery: Max Depth 1-2, Max Devices 200
- Segmentowane skanowanie po VLAN/subnet

### **Najlepsze praktyki:**
- **Włącz LLDP/CDP** dla high confidence links z nazwami portów
- **Użyj autodiscovery** zamiast manual seeds - kompletniejsze wyniki
- **Sprawdź panel Diagnostyka** - uzasadnia każdy link (źródło + statystyki + OID-y)
- **Testuj na małej skali** przed skanowaniem całej sieci
- **Monitoruj czas skanowania** - duże sieci mogą trwać długo

## 14. Bezpieczeństwo i limity

### **Zabezpieczenia aplikacji:**
- ✅ **Read-only SNMP** (GET/WALK/BULKWALK) - brak modyfikacji konfiguracji
- ✅ **Autodiscovery limits** - głębokość, liczba urządzeń, CIDR whitelist/blacklist
- ✅ **Timeout per device** - nie blokuje długo na niedostępnych urządzeniach
- ✅ **Private networks only** - domyślnie tylko sieci prywatne (10.x, 172.16-31.x, 192.168.x)
- ✅ **Credentials security** - SNMP community/hasła v3 nie są logowane w artefaktach

### **Zalecenia produkcyjne:**
1. **Testuj na małej skali** - zacznij od 1-2 seeds z autodiscovery
2. **Ustaw konkretne whitelist** - nie polegaj na domyślnych sieciach
3. **Monitoruj zasoby** - intensywne skanowanie może obciążyć sieć
4. **Sprawdź uprawnienia SNMP** - niektóre urządzenia mogą blokować bulk requests
5. **Używaj w okienku maintenance** - szczególnie dla dużych sieci

---

## 15. Troubleshooting

### **Problem: "Błąd pobierania /api/topology"**
**Rozwiązanie:** Sprawdź czy serwer się uruchomił, port nie jest zajęty

### **Problem: IP nie wyświetlają się**
**Rozwiązanie:** 
1. Sprawdź Console (F12) czy są błędy JS
2. Sprawdź czy checkbox "Pokazuj IP" jest zaznaczony
3. Wykonaj skan rzeczywistych urządzeń (NoOp ma przykładowe IP)

### **Problem: Skan SNMP nie działa**
**Rozwiązanie:**
1. Sprawdź connectivity (ping) do urządzenia
2. Sprawdź SNMP credentials i wersję
3. Sprawdź czy urządzenie ma włączony SNMP (port 161 UDP)
4. Sprawdź firewall

### **Problem: Autodiscovery nie znajduje urządzeń**
**Rozwiązanie:**
1. **Sprawdź czy masz wystarczająco urządzeń** - potrzeba kilku routerów/switchy z SNMP
2. Sprawdź whitelist/blacklist CIDR - może blokuje znalezione IP
3. Zwiększ Max Devices limit (domyślnie 50)
4. Sprawdź czy seed urządzenia mają ARP/routing tables
5. Sprawdź błędy w panelu Diagnostyka → Autodiscovery
6. **W małych sieciach domowych** autodiscovery może nie znaleźć nic nowego

### **Problem: Za dużo/za mało połączeń FDB**
**Rozwiązanie:**
1. Dostosuj próg FDB (2-5 wspólnych MAC-ów)
2. Sprawdź gęstość hostów w sieci
3. Sprawdź panel Diagnostyka → Krawędzie dla szczegółów

---

Autor: Cline (asystent programistyczny)  
Data ostatniej aktualizacji: 2025‑08‑07  
Wersja: v1.1 (z Autodiscovery)
