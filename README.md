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
- [ ] UI:
  - [ ] Sekcja „Ustawienia” (minimalna) + informacja o ścieżce zapisu w Diagnostyce

B. Diagnostyka – realne „evidence” (Etap bieżący, CZĘŚCIOWO WDROŻONE)
- [x] internal/collectors/snmp/gosnmp_collector.go:
  - [x] Per-device: `lldp.localCount/remoteCount`, `fdb.totalEntries`, `vlanCount`, `oidErrors` (część)
  - [x] Per-edge: `source (lldp/cdp/fdb)`, `confidence`, `a:{device,if}`, `b:{device,if}`, `vlan (fdb)`, `sharedMacs`, `sampleMacs[<=5]`, `usedOids[]`
- [x] internal/pipeline/pipeline.go:
  - [x] Przekazanie evidence do UI Topology oraz dalej do `ScanResponse.Diagnostics`
- [x] API `/api/scan`:
  - [x] Uzupełnianie `Diagnostics.Devices/Edges` na podstawie evidence w TopologyPayload
- [ ] Rozszerzenia (następne iteracje):
  - [ ] Per-device: `MgmtIPs` z LLDP mgmtAddress (best‑effort, różne indeksacje vendorowe)
  - [ ] `OidErrors` dla LLDP/IF/CDP (obecnie FDB)
  - [ ] Debug raw: profile LLDP/IF/FDB w `/api/debug/snmpwalk`

C. Ulepszenie skanera (rzetelność topologii)
- [ ] CDP (finalizacja i testy na różnych platformach) – obecnie działa podstawowo
- [ ] IP w grafie:
  - [ ] nodes.data.mgmtIPs + toggle „Pokaż IP pod nazwą” (UI)
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

## 9. Jak uruchomić (stan obecny)

- Dev:
  ```
  go run ./cmd/auditopology
  ```
  UI: http://localhost:5173

- Test skanu (HTTP):
  ```
  POST /api/scan
  {
    "seeds": ["10.0.0.1", "10.0.0.11"],
    "snmpVersion": "v2c",
    "community": "public",
    "fdbThreshold": 3,
    "cdpDebug": true
  }
  ```
  - Odpowiedź zawiera: topology (z Evidence), diagnostics (stats + devices + edges + raw.cdp), a w diagnostics.raw.savedTo jest ścieżka zapisu do workdir/scans/...

- Sprawdzenie projektu po merge:
  ```
  GET /api/project
  ```
  - Zwraca `project.json` (stan połączony z historii skanów)

- UI:
  - Wpisz seedy (IP/FQDN/CIDR – w MVP: IP/FQDN), wybierz SNMP (v2c/v3), „Skanuj”
  - „Diagnostyka” pokazuje statystyki i Evidence (po rozbudowie UI)
  - Eksport grafu: PNG/SVG/PDF

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

## 11. Stan wykonania i TODO

- [x] Endpoint `/api/scan` (SNMP LLDP + IF + FDB korelacja) + Evidence LLDP/CDP/FDB
- [x] Propagacja Evidence: collector → pipeline → API (TopologyPayload + Diagnostics.Devices/Edges)
- [x] Workdir i zapisy artefaktów; project.json z merge (inkrementalny cache + historia)
- [x] Endpointy: `/api/workdir` (GET/POST), `/api/project` (GET), `/api/debug/snmpwalk` (BULKWALK OID)
- [x] UI: formularz skanu + render grafu, eksporty; parsing wielu seedów; panel „Diagnostyka” (UI do podpięcia pełnego Evidence)
- [ ] Diagnostics: MgmtIPs (LLDP mgmtAddress), pełne OidErrors także dla LLDP/IF/CDP
- [ ] Debug profiles w `/api/debug/snmpwalk`: lldp/if/fdb/cdp (predefiniowane listy OID)
- [ ] CDP (hardening i testy wielovendorowe), IP na węzłach + toggle
- [ ] Autodiscovery v1 (ARP/Route/LLDP mgmtAddress; limity, whitelist/blacklist)

## 12. Wskazówki audytowe

- Aby uzyskać „fizyczny” obraz z nazwami portów – włącz LLDP (i CDP w środowiskach Cisco). Linki high będą najwierniejsze.
- Jeśli LLDP/CDP nie jest dostępne, FDB/VLAN korelacja jest użyteczna – ustaw próg odpowiednio do gęstości hostów (2–4).
- Panel „Diagnostyka” oraz Diagnostics w API pozwalają uzasadnić każdy link (źródło + statystyki + OID-y). Surowe zrzuty (raw) pomagają w debugowaniu różnic vendorowych.

## 13. Licencjonowanie i bezpieczeństwo

- Narzędzie działa read‑only (SNMP GET/WALK/BULKWALK).
- Autodiscovery jest kontrolowane: limity hostów, głębokość, biała/czarna lista.
- Wrażliwe informacje (SNMP community/hasła v3) nie są logowane w artefaktach.

---

Autor: Cline (asystent programistyczny)
Data ostatniej aktualizacji: 2025‑08‑06
