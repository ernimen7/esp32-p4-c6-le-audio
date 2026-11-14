# Bluetooth Classic (Soft-BR A2DP + AVRCP) on ESP32-P4 + ESP32-C6

Ten dokument utrwala wszystkie ustalenia inżynierii wstecznej krzemu ESP32-C6 (`libphy.a`, `libbtbb.a`, `libble_app.a` z ESP-IDF v5.5.5) oraz architekturę programowego kontrolera **Soft-BR (Bluetooth Classic Basic Rate, 1 Msps GFSK)** dla M5Stack Tab5 (`ESP32-P4 + ESP32-C6`).

---

## 1. Dlaczego Bluetooth Classic Audio działa na ESP32-C6

1. **Modulacja Basic Rate (BR) jest identyczna z BLE 1M co do szybkości symbolowej i filtru:**
   - Bluetooth Classic BR używa **1 Msps GFSK, $BT = 0.5$** (w specyfikacji Bluetooth A2DP tryb Basic Rate jest **obowiązkowy** w każdym głośniku i słuchawkach; EDR 2/3 Mb/s DPSK jest opcjonalny).
   - Kodek **SBC Joint Stereo** (`44.1 / 48 kHz`, `16 subpasm = 8 × 16 bloków`, `bitpool 35..48`, ~229–305 kb/s) mieści się z >40% zapasem w 3-slotowych pakietach **`DH3`** (`168 B / 2.5 ms = 537.6 kb/s` netto; maks. `183 B / 2.5 ms = 585.6 kb/s`).
2. **Pełna siatka 79 kanałów 1 MHz (`2402..2480 MHz`, parzyste i nieparzyste):**
   - W `phy_hw_freq.o` (`pll_cap_mem_update_new`) syntezator RFPLL kalibruje na starcie wszystkie 85 kanałów co 1 MHz.
   - W `ble_phy.c` (`r_ble_phy_freq_to_chan`) nie ma żadnego asserta na nieparzyste indeksy 1 MHz: wpisanie `chan_1mhz` (`0..78`) do `sch[5]` (`bits [14:8]`) bezpośrednio stroi `2402 + chan_1mhz` MHz.
3. **Natywny tryb surowy `Mode-0` (`sched_type = 5`) w normalnym schedulerze BLE (`r_ble_lll_sched_insert`):**
   - Na podstawie deasemblacji `dtm_hal.c` (`dtm_hal_allocMemory`, `dtm_hal_rstLst`, `dtm_hal_schedEvent`), `ble_lll_sched.c` oraz `ble_lll_mmgmt.c`:
     - Nie są potrzebne żadne dodatkowe hooki symboli w `libble_app.a` (wszystkie istniejące hooki `cis_ll` przechodzą `verify_hooks.py` z wynikiem `RESULT: PASS`).
     - Elementy harmonogramu `sch` z `sched_type = 5` (`*(uint8_t*)(sch + 53) = 5`), unikalnym `sm_num = 0xFE` (`*(uint16_t*)(sch + 32)`) i własnym callbackiem zwolnienia `*(void**)(sch + 64) = br_c6_recycle_cb` są obsługiwane przez stockowy scheduler `r_ble_lll_sched_insert`, koegzystując z BLE, `cis_ll`, Wi-Fi/SDIO i `fw_guard`.

---

## 2. Rejestry i struktury sprzętowe ESP32-C6 (`sch` i `ls`)

### 2.1. Link State (`ls`, 120 B w HP SRAM `0x408xxxxx`)
- **`ls[0]` (`+0x00`)**: `0x8FF00000u | (((uintptr_t)tx_hdr + 4u) & 0xFFFFFu)`
  - Bit 31 = `1` (tryb aktywny), bity `[27:20] = 0xFF` (maks. długość), **bit 28 (`0x10000000`) = `0` — wyłącza sprzętowe wybielanie (BLE whitening)!** (W zwykłym połączeniu BLE `r_ble_lll_conn_reset_link_state` ustawia `0x10000000`, a `dtm_hal_rstLst` jawnie go zeruje maską `0x600F | 0x8FF0`).
- **`ls[1]` (`+0x04`)**: `(ls[1] & 0xF00FFFFFu) | ((tx_pwr_idx & 0x0Fu) << 20)` (moc nadawania, domyślnie indeks `11` / ~9 dBm).
- **`ls[2]` (`+0x08`)**: `0x0FF00000u | (((uintptr_t)rx_hdr + 4u) & 0xFFFFFu)` (deskryptor bufora RX).
- **`ls[5]` (`+0x14`)**:
  - Dla TX: `(ls[5] & 0xF3FFFFFFu) | 0x0C000000u` (bit 26 = TX gotowy).
  - Dla RX: `(ls[5] & 0xF3FFFFFFu) | 0x08000000u`.
- **`ls[9]` (`+0x24`)**: `(ls[9] & 0xFF000000u) | 0x00555555u` (CRC init).
- **`ls[10]` (`+0x28`)**: `(ls[10] & 0xFFFF0000u) | 0x0000FFFFu` (maksymalny priorytet koegzystencji PTI = 15).
- **`ls[11]` (`+0x2C`)**: `0` w trybie RX (`dtm_hal_schedEvent`).
- **`ls[12]` (`+0x30`)**: 32-bitowy `Access Address` (`AA`) dla sprzętowego korelatora.
- **`ls + 0x4C`**: `(*(uint32_t*)(ls + 0x4C) & 0xFFF00000u) | (((uintptr_t)ble_lll_mmgmt_env_p + 0x14u) & 0xFFFFFu)`.
- **`ls + 0x70`**: wskaźnik na blok `user_blk` z ustawionym `user_blk[0x14] = 0x02` (`rxbuffer_reuse_unapply`), dzięki czemu `r_ble_lll_mmgmt_rxbuffer_alloc_precheck` nie dotyka puli buforów BLE.

### 2.2. Schedule Item (`sch`, 72 B w HP SRAM `0x408xxxxx`)
- **`sch + 2` (`uint8_t`)**: `(b2 & ~0x50u) | 0x10u` dla **Single TX**, `(b2 & ~0x50u) | 0x40u` dla **Single RX**.
- **`sch[1]` (`+0x04`)**: `(sch[1] & 0xFF000000u) | ((uintptr_t)ls & 0xFFFFFu)` (`Mode 0` w bitach `[23:20] = 0`).
- **`sch[4]` (`+0x10`)**: `(sch[4] & 0x0FFFFFFFu) | 0x00100000u` (`PHY 1M = 0` w bitach `[31:28]`).
- **`sch[5]` (`+0x14`)**: `(sch[5] & 0xFFFF8000u) | ((chan_1mhz & 0x7Fu) << 8) | 0x7Fu` (`chan_1mhz = 0..78`, priorytet `15`).
- **`sch[6]` (`+0x18`)**: `|= 0x18000000u`.
- **`sch[7]` (`+0x1C`)**: `(0x000Fu << 16) | (rx_sync_win_us & 0xFFFFu)` — dolne 16 bitów to **okno poszukiwania korelacji SyncWord w µs** (gdy brak korelacji w tym oknie, sprzęt kończy RX natychmiast; gdy korelacja nastąpi, odbiera pełne `RXD_LEN` bajtów!).
- **`sch + 32` (`uint16_t`)**: `0x00FEu` (`sm_num`).
- **`sch[10]` (`+0x28`)**: `0` przed wstawieniem (sprzęt zapisuje tu flagi statusu wykonania).
- **`sch[11]` (`+0x2C`)**: `air_start_us - (*ble_lll_sched_env_p)` (uwzględnia czas rozgrzania radia/PLL `sched_lead`, ok. `150..192 µs`).
- **`sch[12]` (`+0x30`)**: `air_end_us`.
- **`sch + 52` (`uint8_t`)**: `0` (korekcja mikrosekundowa).
- **`sch + 53` (`uint8_t`)**: `5` (`sched_type = 5`).
- **`sch + 55` (`uint8_t`)**: `0` przed wstawieniem; `bit 1 (0x02)` ustawiany przez scheduler, gdy slot został pominięty/wywłaszczony.
- **`sch + 64` (`void *`)**: `br_c6_recycle_cb`.

### 2.3. Filtr Gaussa 1M GFSK (opcjonalny przełącznik dewiacji)
- Rejestry `0x600A20E0..0x600A20EC` (`bt_bb_v2.o: set_gauss_coeff_1m`): opcjonalne skalowanie współczynników o `0.64` ($h = 0.50 \to h = 0.32$) na czas aktywności BR i przywracanie wartości fabrycznych dla BLE.

---

## 3. Kodowanie pakietów w eterze (obejście korelatora 32-bitowego)

1. **SyncWord (`br_syncword_from_lap`):**
   - Generator BCH `(64, 30)` $g(D) = \text{0260534236651}_8 = \text{0x585713DA9}$, sekwencja PN $P_{64} = \text{0x83848D96BBCC54FC}$ (`bit 0` nadawany jako pierwszy w eterze).
   - Zweryfikowano względem wektora Core Spec dla `GIAC = 0x9E8B33`: `sw_air = 0x4E7A2CCE331A3AE2` (odwrócony zapis MSB-first w specyfikacji: `0x475C58CC73345E72`).
   - Górne 30 bitów `sw_air[63:34]` są równe `a_tilde = (barker6 << 24) | LAP[23:0]` (`P` znosi się przy podwójnym XOR), więc **bajt 5 słowa synchronizacji (`sw_air[47:40]`) jest dokładnie równy `(LAP >> 6) & 0xFF`!**
2. **TX (`TX-in-Payload` — domyślny, uniwersalny):**
   - Start `64 µs` przed nominalną granicą slotu (`anchor_us - 64`), `AA = 0x55555555`, `TXD_HDR = 0x05`, `TXD_LEN = N`.
   - `TXD_PAYLOAD[0] = (sw_air & 1) ? 0x55 : 0xAA` (preambuła z czystym przejściem w `s[0]`), a kolejne bajty zawierają pełny 64-bitowy `sw_air`, 4-bitowy trailer, 54-bitowy nagłówek `1/3 FEC` oraz wybielony ładunek z `CRC-16` (do `DH3` włącznie, `N <= 225 B <= 255 B`).
3. **RX (100% natywna korelacja jedno-slotowa):**
   - **Inquiry `FHS` (`GIAC = 0x9E8B33`):** `AA = 0x331A3AE2`, bajt 5 (`RXD_LEN`) = **`0x2C = 44 B`** (`424 µs < 625 µs`), co przechwytuje cały pakiet `FHS` głośnika (`40 B`).
   - **Page Slave Response / ACK (`ID` na `DAC`):** `AA = DAC[31:0]`, okno ograniczone do `200 µs`.
   - **Połączenie ACL (`CAC` naszego Mastera):** funkcja `br_derive_c6_bdaddr()` generuje z fabrycznego MAC-a unikalny adres `BD_ADDR` z **`LAP[13:6] = 0x2E` (`46 B`)** oraz sprawdzoną jakością autokorelacji `AA`. Wysyłając głośnikowi `LMP_max_slot(1)`, gwarantujemy, że każdy pakiet Slave->Master (`NULL`, `POLL`, `DM1`, `DH1`) mieści się w `46 B` (`444 µs < 625 µs`).
4. **Wyjątek wybielania (Data Whitening) dla pakietu `FHS` (Core Spec Vol 2 Part B §7.2):**
   - W stanie połączenia LFSR `D^7 + D^4 + 1` jest inicjowany przez `0x40 | CLK[6:1]` (`[1, CLK6..CLK1]`).
   - Dla `FHS` w `Master Page Response` oraz `Inquiry Response` LFSR w systemie 79-kanałowym jest inicjowany **dwoma bitami MSB równymi `1`**: `0x60 | (X & 0x1F)` (`[1, 1, X4..X0]`). Na odbiorze `Inquiry FHS` dekoder wspiera również szybkie przeszukanie stanów LFSR, weryfikowane jednocześnie przez 8-bitowy `HEC(DCI=0)` i 16-bitowy `CRC16(DCI=0)`.
5. **Harmonogram sub-trainów 8-kanałowych (`10.0 ms < 11.25 ms`):**
   - Standardowe okno skanowania głośnika `T_w_scan = 11.25 ms` (18 slotów) na pojedynczej częstotliwości.
   - Dzieląc 32 częstotliwości Train A / Train B na 4 pod-pociągi po 8 kanałów (`8 × 1.25 ms = 10.0 ms < 11.25 ms`), obsługujemy każdy kanał pełną parą slotów `625 µs TX + 625 µs RX`, eliminując wyścigi pół-slotowe (`312.5 µs` vs `~192 µs` `sched_lead`) przy zachowaniu deterministycznego trafienia w okno skanowania.

---

## 4. Podział ról ESP32-C6 ↔ ESP32-P4

- **`br_ll/` (przenośny C11, bez zależności od ESP-IDF):**
  - `br_proto`, `br_hop`, `br_air`, `br_crypto` (`SAFER+` `E1/E21/E22/E3`, redukcja $K'_c$, szyfr strumieniowy `E0`, `SSP` `f1/f2/f3/g`), `br_engine`.
- **`c6_firmware/` (`v1.5.0`):**
  - Cienki adapter `br_c6_radio.c` + `br_c6_core.c` + bezpiecznik `br_c6_crash.c` (wyłącza Soft-BR po 2 resetach paniki, zachowując nietykalny `fw_guard`).
  - Koegzystuje w `slave_bt.c` obok `cis_c6_*` (uchwyt Classic ACL `0x0B00`, komendy Classic + vendor `0xFC31` `'BRC6'`).
- **`p4_bt_classic/` (ESP32-P4):**
  - Współdzielony multiplekser HCI H4 w `esp_hosted` (bezkolizyjna praca `p4_le_audio` i `p4_bt_classic` w jednym firmware).
  - Pełny stos hosta Classic: **LMP** (Legacy PIN `"0000"`/`"1234"` + SSP P-192 ECDH „Just Works”, `LMP_max_slot(1)`, szyfrowanie `E0`, AFH), **L2CAP** (`SDP 0x0001`, `AVDTP 0x0019`, `AVRCP 0x0017`), **SDP**, **AVDTP 1.3 Source**, **AVRCP** oraz **koder stereo SBC** (8 pasm, Joint Stereo, 44.1/48 kHz).
- **`examples/tab5_player/`:**
  - Obsługa zarówno głośników/słuchawek **Bluetooth Classic (A2DP/SBC)**, jak i słuchawek **LE Audio (CIS/LC3)** w jednym odtwarzaczu na M5Stack Tab5, z ręcznym wyborem urządzenia z listy skanowania, kluczem parowania serwowanym z pamięci RAM i jawnym przyciskiem aktualizacji C6 (`1.5.0`).

---

## 5. Wyniki na sprzęcie

### 2026-11-10 — pierwszy przebieg na Tab5 (obraz testowy strażnika z `CONFIG_CYBERDECK_BR_SELFTEST`)

Do tego dnia wszystkie dowody działania Soft-BR pochodziły z testów hosta i z symulatora `br_ll/sim` (obie strony łącza
z tego samego kodu). Pierwszy przebieg na prawdziwym radiu:

- Host: Tab5 z firmware Cyberdeck (P4 `4ef44bb85`), C6 przed testem 1.4.85. Obraz testowy wgrany przez `/api/c6/ota`
  (`c6_ota.py --expect-rollback --expect 1.5.49`), odczyt śladu przez `tools/br_selftest.py`. Głośnik Classic w trybie
  parowania obok urządzenia.
- Obraz wystartował (C6 zgłaszał 1.5.49), nie było awarii ani zawieszenia, Wi-Fi i HCI działały przez całe 10 minut,
  strażnik wrócił sam do 1.4.85 po 616 s (`crashes_in_cis` 0).
- Liczniki przez całą próbę bez zmian: `insert ok 2, fail 0, tx done 1, rx done 0, captured 0, skipped 0`; silnik
  w stanie 1 (inquiry), runda 1, `slots tx 1 rx 0`. Czyli: `r_ble_lll_sched_insert` przyjął oba elementy
  `sched_type = 5`, slot TX wykonał się i wrócił przez `br_c6_recycle_cb`, slot RX nigdy nie wrócił (ani jako
  wykonany, ani jako pominięty), a silnik czekał na niego bez końca — także limit czasu inquiry (10,24 s) go nie
  zakończył. Werdykt narzędzia: `RX_NEVER_RETURNS`.

Wniosek: twierdzenie z rozdziału 1 pkt 3, że elementy `sched_type = 5` obsługuje w całości stockowy scheduler, jest
potwierdzone tylko dla nadawania. Odbiór w tej postaci nie działa.

### Co robi oryginalny tryb testowy (deasemblacja `dtm_hal.c.o`, `libble_app.a` ESP-IDF 5.5.5)

`dtm_hal_schedEvent(ctx, mode)` nie wywołuje `r_ble_lll_sched_insert`:

- wypełnia element harmonogramu (kanał w `sch[5]` bity 14:8, PHY w `sch[4]`, `sch + 2`: `0x10` TX / `0x40` RX,
  `sch[5]` dolna czwórka = 3), start = teraz + `ble_lll_module_env_p[3]` + 500 + wyprzedzenie harmonogramu,
- **RX: `ls[11] = 0`, `sch[7] = 0x000F0001`, czas zdarzenia 1000 us** (adapter Soft-BR wpisuje `0x000F0001` dla TX,
  a dla RX `(0x000F << 16) | okno_us` — tej postaci oryginał nie używa),
- gdy trzeba, instaluje własną obsługę przerwania radia `dtm_hal_isr` (`dtm_hal_isrInit`: kasuje stany przerwań
  `0x600A1308` / `0x600A1318` i zgłasza zdarzenie `dtm_hal_recycleInTask`, które woła callback z `sch + 64`),
- woła `r_ble_phy_disable()`, **wpisuje adres elementu wprost do rejestru `0x600A18FC`** i `r_ble_lll_sched_run()`.

Adapter Soft-BR idzie inną drogą (kolejka stockowego harmonogramu, stockowe przerwanie LL), więc koniec zdarzenia RX
bez synchronizacji trafia do kodu, który elementu typu 5 nie zwalnia.

### 2026-11-10 — drugi przebieg: sondy slotu RX (ślad `0xB5` / `0xB6`)

Obraz testowy z sondami (`br_c6_st_stuck`, `br_c6_st_force`, `br_c6_st_lone_rx`; próba strażnika skrócona do 7 minut,
powrót do 1.4.85 po 462 s, bez awarii). Sonda patrzy co 2 s na sloty po zaplanowanym końcu i próbuje je odzyskać:
najpierw `r_ble_lll_sched_delete_by_sm_num_and_type`, przy następnym tyknięciu `r_ble_phy_disable()`.

Zmierzone (14 slotów RX: 2 samotne na kanale 0 z adresem dostępu rozgłaszania BLE, 20 ms i 500 us, oraz sloty RX
kolejnych par inquiry):

- żaden slot RX nie wrócił sam, niezależnie od długości okna i od tego, czy poprzedzał go slot TX;
- 2 s po końcu: rejestr stanu pasma podstawowego `0x600A1900` ma bit 31 = 0 (nic nie trwa), a jego dolne 20 bitów
  rosną dokładnie o rozmiar jednego slotu adaptera (`0x3A4`) na kolejny slot — wskazuje więc na pamięć tego slotu;
  rejestr `0x600A18FC` = 0; słowo 0 elementu zmienia się z `0x00100000` na `0x00400000`; bajt `sch + 55` = 0 (nie
  pominięty);
- `sched_delete` zwraca 0 usuniętych — harmonogram programowy już elementu nie trzyma;
- po `r_ble_phy_disable()` i ręcznym zwrocie slotu następna para idzie normalnie (`tx done` rośnie 1 → 5).

Wniosek: pasmo podstawowe **wykonuje i kończy** samotny element RX typu 5, ale stockowe przerwanie
(`r_ble_phy_isr`) nie zgłasza jego końca, więc `r_ble_lll_recycle_sch_entry` się nie wykonuje i callback z `sch + 64`
nie jest wołany. Oryginalny tryb testowy ma na to własne przerwanie (`dtm_hal_isr`: każde przerwanie = koniec
elementu). Poprawka po stronie adaptera: slot RX odbierać po czasie — po zaplanowanym końcu sprawdzić bit 31 rejestru
`0x600A1900` i samemu przeczytać bufor RX.

Czego ten przebieg nie pokazał: czy cokolwiek zostało odebrane. Zwrot wymuszony przez sondę oznaczał slot jako
pominięty, więc bufor RX nie był czytany (`captured 0` nic tu nie znaczy). Po 8 wymuszonych zwrotach sloty się
skończyły (wycofane po `r_ble_phy_disable()`), dlatego rundy 3–18 nie wysłały już nic.

### Następny krok (przygotowany w kodzie, nie sprawdzony na sprzęcie)

Obraz testowy, w którym sonda co 20 ms odbiera zakończone sloty RX bez zatrzymywania radia (`br_c6_st_force` krok 1
przy bicie 31 = 0 woła callback tak, jak zrobiłoby to przerwanie) i pięć samotnych okien RX po 60 ms na kanale
rozgłaszania BLE. Odpowiedzi, których ma dostarczyć: czy bufor RX zawiera odebrany pakiet (`captured` > 0, ślad
`0xB3`), czy harmonogram przyjmuje ponownie element, którego sam nie zwolnił (`insert fail`, `tx done` w kolejnych
parach), i czy przy ~50 parach na sekundę inquiry znajdzie urządzenie Classic w trybie widoczności.

Docelowo odbiór po czasie należy do adaptera (`br_c6_radio.c`), nie do sondy testowej: zegar LL ustawiony na koniec
okna RX, w nim odczyt bufora i zwrot slotu. Silnik `br_ll` powinien też kończyć inquiry po czasie niezależnie od
wyniku slotu. Jeden cykl wgrania to ok. 9 minut (7 minut próby strażnika); nowy obraz testowy wolno wgrać dopiero po
powrocie C6 do potwierdzonego wsadu, inaczej nadpisze się punkt powrotu.

### 2026-11-10 (druga sesja) — odbiór po czasie w adapterze, obraz testowy pod hostem Classic

Zmiany w kodzie, **zbudowane (`RESULT: PASS`), niesprawdzone na sprzęcie** (Tab5 był poza siecią):

- **Adapter (`br_c6_radio.c`, każdy obraz):** `br_c6_radio_service` odbiera każdy slot RX po jego zaplanowanym
  końcu (+40 µs): gdy pasmo podstawowe nie trzyma już elementu, usuwa go z kolejki harmonogramu (element, który
  nigdy nie ruszył, wraca jako pominięty) i woła callback tak, jak zrobiłoby to przerwanie. Element trzymany
  jeszcze 600 µs po końcu (bajt długości bierze się z eteru i może żądać 255 bajtów) dostaje `r_ble_phy_disable()`
  i wraca jako pominięty; gdy pasmo nadal na niego wskazuje, slot jest wycofany. Budzi zegar `esp_timer` ustawiony
  na najbliższy koniec slotu RX (`br_c6_rx_timer_arm`, zdarzenie w zadaniu LL). Sloty są przydzielane po kolei, więc
  slot odebrany przez adapter jest używany ponownie jako ostatni. `br_c6_cancel_all` zwalnia element usunięty
  z kolejki od razu.
- **Silnik (`br_engine.c`):** para TX+RX ma limit czasu (koniec okna RX + 2,5 ms); po nim silnik porzuca parę
  (`pairs_lost`) i planuje następną, a spóźniony raport porzuconej pary jest odrzucany. Brak raportu RX nie
  zatrzymuje już silnika i inquiry kończy się w swoim czasie (test hosta `test_engine`, punkt 4).
- **Obraz testowy (`CONFIG_CYBERDECK_BR_SELFTEST`):** nie gubi już zdarzeń bezwarunkowo. Pod hostem bez Classic
  (Cyberdeck) działa jak dotąd: sam robi inquiry i pisze ślad. Pierwsza komenda Soft-BR albo pakiet ACL od hosta
  (`tab5_player` zaczyna od `BR_VS_PING`) przełącza go: koniec własnych inquiry i sond, zdarzenia idą do hosta,
  ślad zapisuje się dalej (`0xB4` z kodem 2, nowy rekord `0xB7`: sloty odebrane przez adapter, zatrzymane po
  końcu, wycofane, pary porzucone przez silnik). Sonda co 20 ms zgłasza już tylko sloty, których adapter nie
  odebrał w 20 ms.

Tempo, którego należy się spodziewać: silnik planuje następną parę dopiero po raporcie RX, a raport przychodzi
ok. 550–800 µs po początku slotu RX, więc pakiet jednoslotowy idzie co 2,5 ms, a `DH3` co 3,75 ms (do 390 kb/s
przy 183 B) — wystarcza na SBC 229 kb/s, bez dużego zapasu na retransmisje.

Czego nadal nie wiadomo (rozstrzyga pierwszy przebieg): czy bufor RX zawiera odebrany pakiet; czy pasmo kończy
element dokładnie na `sch[12]`, także gdy bajt długości z eteru żąda więcej (odpowiedź `ID` przy wywołaniu: bajt
długości to `(LAP >> 6) & 0xFF` wywoływanego urządzenia); czy bit 31 rejestru `0x600A1900` znaczy „trwa” także
w trakcie elementu; czy harmonogram przyjmuje ponownie element, którego sam nie zwolnił.

### Jak wygląda próba dźwięku (cały łańcuch jest w repozytorium, nic z niego nie grało na sprzęcie)

P4 w firmware Cyberdeck nie ma stosu Classic. Stos hosta (`p4_bt_classic`) działa w `examples/tab5_player`, który
ma ten sam układ partycji co Cyberdeck i nigdy się nie potwierdza: wgrany przez OTA do nieaktywnego slotu wraca do
Cyberdeck przy następnym resecie P4. Kolejność jednej próby (ok. 9 minut, właściciel przy urządzeniu, głośnik
w trybie parowania, karta SD z plikami `/sd/music/*.mp3`):

1. Cyberdeck: `c6_ota.py` z obrazem testowym (`build_guardtest`), start 7-minutowej próby strażnika.
2. Cyberdeck: OTA `examples/tab5_player/build/tab5_player.bin` do nieaktywnego slotu P4 (`ota.py --bin ...
   --no-confirm-wait --no-assets`). Restart P4 w trakcie próby C6 jest dozwolony (czas próby sumuje się, limit 10
   startów).
3. Na ekranie: Scan / Pair, wybór głośnika, Play. Odtwarzacz nie ma sieci, więc śladu C6 nie da się w tym czasie
   czytać; po powrocie do Cyberdeck ślad jest już pusty (C6 po wycofaniu startuje od nowa).
4. Po 7 minutach C6 wraca do potwierdzonego wsadu; reset P4 przywraca Cyberdeck.

Zdalna próba bez dotykania ekranu wymagałaby wbudowania `p4_bt_classic` w Cyberdeck (brakuje tam
`esp_hosted_cyberdeck_add_hci_rx_cb`, `_connect`, `_transport_up` w łatce esp_hosted i punktu `/api/diag`).

### 2026-11-10 (wieczór) — obce repozytorium `ProgrammingAce/tab5-a2dp`: co zmierzyli i co z tego dla nas

Publiczne repozytorium (jeden commit z 2026-11-10) zbudowane na firmware C6 tego projektu: 174 ze 192 plików
katalogu C6 są identyczne z naszymi, nowa jest warstwa Classic (`c6_firmware/main/radio_lab.c`, 2375 linii),
biblioteka `components/br_baseband` i aplikacja P4. Przeczytane statycznie w odizolowanym katalogu, nic nie budowano
ani nie uruchamiano. Ich własne pliki nie mają licencji („no blanket license”) — **kodu nie kopiujemy**; fakty
zmierzone na sprzęcie i opis mechanizmu są do wykorzystania.

Stan według nich samych: wersja laboratoryjna (LMP/L2CAP/AVDTP sterowane z komputera) **grała na głośniku Bose**;
wydzielona aplikacja P4 z README ma zapisane parowanie, ale próba połączenia skończyła się limitem czasu i dźwięku
z niej nie potwierdzono.

Ten sam pomysł, inne podłoże:

| | tab5-a2dp | Soft-BR (to repozytorium) |
|---|---|---|
| Podłoże radia | prawdziwa sesja trybu testowego DTM; haki na `dtm_hal_rstLst`, `r_ble_lll_sched_run`, `dtm_hal_schedEvent`, `dtm_hal_isr`, `r_ble_phy_isr`, `r_ble_lll_get_rxed_buffer` (11 haków) | własne elementy `sched_type = 5` w kolejce stockowego harmonogramu, zero haków |
| Koniec zdarzenia RX | zgłasza go `dtm_hal_isr` sesji DTM — działa na sprzęcie | stockowe przerwanie go nie zgłasza (rozdz. 5); odbiór po czasie w adapterze, nie sprawdzony |
| Rytm | para TX/RX co 1250 us, zdarzenie co 625 us | jedna para naraz, 2,5 ms na pakiet jednoslotowy |
| Wi-Fi i BLE w czasie Classic | wyłączone (tryb BR zabiera radio) | zostają (elementy idą przez harmonogram z koegzystencją) |
| Pakiety, dźwięk | tylko jednoslotowe, SBC bitpool 14 (ok. 113 kb/s) | DH3, cel 229 kb/s |
| AFH, AVRCP, SDP | brak | są w kodzie |
| Dowód ze sprzętu | inquiry, page, połączenie, LMP, SSP, E0, strumień (wersja laboratoryjna) | tylko nadawanie |

Zmierzone u nich, ważne dla naszego adaptera (numery to ich wersje C6 z komentarzy):

1. **Modem BLE odbiera pakiety Classic.** Adres dostępu = bity 0..31 słowa synchronizacji, dalsze bajty lądują
   w buforze RX od `data + 28`, znacznik czasu dopasowania w `data + 16`, stan w `data + 12`. To odpowiada na pytanie
   otwarte u nas od pierwszego przebiegu.
2. **Przepis na zdarzenie RX, który u nich działa** (`lab dtmhop … rx 0 700 1`): `ls + 44` = długość okna RX w us
   (700 dla page i połączenia, 1050 dla inquiry; `0` = słuchaj do pierwszego pakietu, `0x3FFFFFFF` = ciągle),
   `sch + 28` = 255, `sch + 48` = start + 1. U nas: `ls[11] = 0`, `sch[7] = 0x000F0000 | okno`, `sch[12]` = koniec
   okna. Trzy pola różnią się od przepisu sprawdzonego na sprzęcie.
3. **Bajt długości BLE to bity 40..47 słowa synchronizacji** (1.4.233) — to samo, co przyjęliśmy. Dla pakietu ID
   w odpowiedzi na page ten bajt wynika z adresu głośnika i bywa duży: odbiornik „odbiera” wtedy do 255 bajtów szumu
   i nie zdąża zwolnić radia przed FHS. Ich wyjście (1.4.229–1.4.232): maksymalna długość RX w `ls + 8` bity 20..27
   ustawiona nisko (4) na okna, w których liczy się samo dopasowanie; wykrycie po świeżym znaczniku czasu i pierwszym
   bajcie po adresie dostępu.
4. **Bufory RX trzeba oddawać** (1.4.236): po poprawnych odbiorach pierścień buforów się kończy i odbiór staje;
   pętla `r_ble_lll_get_rxed_buffer` → `r_ble_lll_append_rx_buffer`, jak w `dtm_hal_recycleSchItem`. U nas każdy slot
   ma własny bufor poza pulą (`user_blk[0x14] = 2`) — do sprawdzenia w śladzie, czy to wystarcza.
5. **Nadawanie po odbiorze** (1.4.228): `sch + 44` = start − wyprzedzenie; TX po oknie RX sięgającym ok. 1028 us
   jest po cichu gubiony. Przy naszych 2,5 ms na parę zapas jest duży.
6. **Uśpienie zegara** (1.4.199): po `r_ble_lll_sleep_enable_now` zegar LL staje; w sesji DTM wołają
   `r_ble_lll_sleep_disable(0)`.
7. **Licznik zdarzeń liczyć z czasu, nie z wywołań** (1.4.237): poprawny odbiór potrafi wywołać planistę dodatkowy
   raz i odwrócić parzystość TX/RX.

Zmierzone konwencje hosta (z ich `br_a2dp_src.h`, „ported from the lab tools that streamed to a Bose speaker”) —
lista kontrolna dla `p4_bt_classic`, który nie rozmawiał jeszcze z żadnym urządzeniem:

- wartości 128-bitowe LMP i współrzędne P-192 w kolejności little-endian; IOcap w `f3` w kolejności z LMP;
- `Kc` z ACO ostatniego uwierzytelnienia;
- `LMP_accepted(start_encryption_req)` od głośnika jest już zaszyfrowane: deszyfrowanie RX włączyć przed wysłaniem
  `start_encryption_req`;
- `setup_complete` dopiero po `accepted(host_connection_req)`;
- sparowany głośnik potrafi sam otworzyć kanał AVDTP.

Decyzja robocza: nie przechodzimy na ich kod. Pierwsza próba idzie na naszym obrazie, a przed nią warto dodać do
obrazu testowego drugi przepis RX (pkt 2) jako wariant porównywany w tej samej próbie. Gdyby odbiór przez kolejkę
harmonogramu nie dał się uruchomić, sprawdzonym podłożem zastępczym pod silnik `br_ll` jest sesja DTM (własne
przerwanie, haki na `dtm_hal_rstLst` i `r_ble_lll_sched_run`) — do napisania od nowa według opisu, nie przez kopię.

### 2026-11-10 (wieczór) — trzeci i czwarty przebieg: odbiór działa, ciszę powodowało okno szukania adresu dostępu

Obie próby pod Cyberdeck, ślad czytany przez `tools/br_selftest.py`, właściciel przy urządzeniu, głośnik w trybie
parowania. Dzienniki obok skryptów Wi-Fi w drzewie roboczym Cyberdeck (`local/proba-2026-11-10/`, poza gitem).

**Trzeci przebieg (20:35, obraz z drugiej sesji bez zmian).**

| Co | Wynik |
|---|---|
| Wstawienia do harmonogramu | 12 985 przyjętych, 0 odrzuconych |
| Sloty TX wykonane | 6490 |
| Sloty RX odebrane przez `br_c6_radio_service` | 6494, 0 zatrzymanych po czasie, 0 wycofanych, 0 par porzuconych |
| „Przechwycenia” | 6494 z 6494 slotów RX, wszystkie z długością 0, nagłówkiem 0 i tym samym bajtem RSSI |
| Sondy na kanale 37 (5 × 60 ms) | nic |
| Wynik wyszukiwania | 0 urządzeń |

- Problem z pierwszych przebiegów (slot RX nie wraca) jest rozwiązany: adapter sam odbiera każdy slot RX po jego
  końcu, w pełnym tempie par.
- Kryterium „odebrano pakiet” było błędne. Pasmo podstawowe nadpisuje słowo stanu bufora (`+12`) na końcu każdego
  okna, także pustego, więc „stan inny niż `0xFFFFFF`” nie znaczy nic. Werdykt czytnika `SYNC_ONLY` z tego
  przebiegu jest fałszywy.
- C6 przestał odpowiadać hostowi w drugim wyszukiwaniu: P4 zgłosił `sdmmc_send_cmd returned 0x107` i zrestartował
  się, dwa razy z rzędu przy tym samym czasie pracy P4 (167,85 s i 167,73 s) i tym samym ostatnim liczniku
  (6490 slotów TX).

**Czwarty przebieg (21:00).** Zmiany w obrazie testowym: odbiór rozpoznawany po bajtach za adresem dostępu
(zerowanych przed każdym oknem), sondy z czterema przepisami elementu RX po kolei (`br_c6_rx_recipe_t`), każda
szuka adresu dostępu przez całe okno, rekord zdrowia (sterta, zegar kontrolera, liczba przebiegów adaptera),
licznik awarii bezpiecznika w śladzie.

| Przepis elementu RX | Okna 60 ms | Z odebranymi bajtami | Poprawny nagłówek rozgłoszeniowy BLE po zdjęciu wybielania |
|---|---|---|---|
| 0 „stock”: bez okna w stanie łącza, słowo 7 = `0x000F0000 \| czas szukania` | 48 | 48 | 48 |
| 1: okno w `ls+44`, słowo 7 = 255, koniec elementu = start + 1 | 48 | 48 | 47 |
| 2: okno w `ls+44`, słowo 7 = 255, koniec elementu = koniec okna | 48 | 48 | 45 |
| 3: bez okna, słowo 7 = 255 | 48 | 48 | 48 |

Słowo stanu po odebranym pakiecie: młodsze 24 bity `0x000010` we wszystkich 192 oknach (CRC nie może się zgadzać,
bo sprzętowe wybielanie jest wyłączone), najstarszy bajt to RSSI (−92…−28 dBm, mediana −71). Słowo `+16` to
znacznik czasu odbioru w zegarze kontrolera. Te same nadajniki wracają w kolejnych oknach (35 różnych początków
pakietu na 192 okna, najczęstszy 25 razy), więc to są pakiety z eteru, nie szum.

Co z tego wynika:

1. Surowy element RX wstawiony do zwykłego harmonogramu odbiera pakiety. Sesja DTM nie jest do tego potrzebna.
2. Młodsza połowa słowa 7 elementu to czas szukania adresu dostępu w mikrosekundach. Sondy trzeciego przebiegu
   słuchały przez 112 µs z każdych 60 ms i dlatego nic nie odebrały. To samo ustawienie (80 + 32 µs) mają sloty RX
   silnika.
3. Pola z obcego repozytorium (okno w `ls+44`, 255 w słowie 7, koniec elementu tuż po starcie) działają także
   w naszym trybie, ale żadne z nich nie jest warunkiem odbioru.
4. Sprzętowe wybielanie jest wyłączone tak, jak zakłada adapter: bajty za adresem dostępu dają poprawny nagłówek
   dopiero po programowym zdjęciu wybielania kanału 37.

Wyszukiwanie w tym przebiegu szło jeszcze z czasem szukania 112 µs: 1600 par, 0 dopasowań. C6 wywrócił się
w pierwszym wyszukiwaniu, w obu uruchomieniach po rekordzie z 1600 slotami TX, przed rekordem z 2400 (4–6,5 s od
startu wyszukiwania). Co wiadomo o tej awarii:

- licznik bezpiecznika Soft-BR wzrósł z 0 do 1, a zapisuje go tylko start po resecie awaryjnym układu z aktywnym
  Soft-BR, więc C6 resetuje się sam (panika albo watchdog przerwań), a nie jest zagłodzony;
- wolna sterta stoi w miejscu (106–108 kB), zegar kontrolera idzie równo z `esp_timer`, adapter nie kręci się
  w pętli (ok. 450 przebiegów na sekundę, jeden na parę);
- miejsce awarii zależy od obrazu (poprzedni: po 6490 parach, ten: po 1600), w danym obrazie jest powtarzalne;
- pamięć RTC nie przetrwała resetu pinem, którym host podnosi C6 po awarii (brak rekordu `0xBA`), więc zapis
  miejsca awarii musi trafić do NVS przy starcie pośrednim.

### 2026-11-10 (wieczór) — piąty przebieg: wyszukiwanie znajduje głośnik; awaria to pętla w przerwaniu radia

Zmiany w obrazie testowym przed tym przebiegiem (21:10): każdy slot RX otwiera się 100 µs przed granicą slotu
i szuka adresu dostępu do swojego końca (`BR_RX_EARLY_US`; pole `rx_sync_win_us` żądania nie jest już używane),
rekord czasu przyjścia przechwyconego pakietu (`0xBF`), zapis awarii: owinięty `esp_panic_handler` zapisuje miejsce
do pamięci RTC, start po resecie awaryjnym przenosi je do NVS, każdy start obrazu oddaje je w śladzie
(`0xBC`–`0xBE`).

| Co | Wynik |
|---|---|
| Wyszukiwanie GIAC, pierwsze uruchomienie | głośnik właściciela znaleziony w pierwszych 800 parach (2 s): klasa `0x240404`, −52 dBm |
| Wyszukiwanie GIAC, drugie uruchomienie (po awarii) | ten sam głośnik, −49 dBm |
| Pakiety FHS | 3 z 3 i 4 z 4 z poprawnym HEC i CRC |
| Czas przyjścia (znacznik odbioru minus granica slotu) | +42…+44 µs we wszystkich siedmiu |
| Werdykt czytnika | `INQUIRY_WORKS` |

Adres głośnika zgadza się z tym, który jego właściciel odczytał z laptopa. To pierwszy dowód na sprzęcie, że pakiet
ID nadany przez adapter jest poprawnym pakietem Classic (głośnik na niego odpowiedział) i że tor odbioru dekoduje
pakiet z FEC 2/3. Odpowiedź przychodzi 42–44 µs po granicy slotu, czyli tyle, ile trwa preambuła i pierwsze 32 bity
słowa synchronizacji plus kilka mikrosekund: rozkład czasu w silniku jest dobry. Wąskie okno poprzednich
przebiegów (112 µs) kończyło się przed tym momentem albo tuż przy nim.

Awaria, zapis z NVS:

- reset przez watchdog przerwań („Interrupt wdt timeout on CPU0”), zadanie `ble_ll`;
- licznik rozkazów w `r_ble_lll_sched_check_remaining_entries`, wywołanej z `r_ble_phy_isr`: pętla idąca po kolejce
  elementów harmonogramu (początek w środowisku harmonogramu `+4`, następny element w słowie 0, 20 bitów);
- ostatni przebieg adaptera 58,7 s od startu C6, 2585 slotów TX.

Pętla nie ma końca, gdy element jest w kolejce dwa razy. Adapter mógł do tego doprowadzić: zakończony slot RX
zabiera według czasu, nie według zgłoszenia kontrolera, a nowy element budował w slocie bez sprawdzenia, czy
kontroler nie ma jeszcze poprzedniego w kolejce (`r_ble_lll_sched_delete_by_sm_num_and_type` zwraca wtedy 0).
Czasy awarii od startu C6 w trzech obrazach: 162,5–164,5 s, 56,5–59 s, 58,7 s, czyli co ok. 52 s; coś w kontrolerze
albo hoście dzieje się w tym rytmie i wtedy element Soft-BR zostaje w kolejce dłużej. Co to jest, nie ustalono.

Poprawka (w kodzie, `RESULT: PASS`): `controller_links()` w `br_c6_radio.c`. Slot nie jest używany ponownie, dopóki
jego element jest elementem przekazanym pasmu podstawowemu albo jest w kolejce kontrolera; zakończony slot RX
w takim stanie jest oglądany ponownie po 500 µs. Liczniki obu sytuacji są w rekordzie `0xB7`.

### 2026-11-10 (wieczór) — szósty i siódmy przebieg: awarię wyzwala skan LE hosta; rozdzielenie na granicy HCI

**Szósty przebieg (21:20)**, obraz z `controller_links()`: awaria wróciła w tym samym miejscu (57,8 s od startu
C6, 2187 slotów TX), a liczniki nowego zabezpieczenia w rekordzie `0xB7` stały na zerze do ostatniego odczytu.
Ponowne użycie slotu, którego element kontroler ma jeszcze w kolejce, nie jest więc przyczyną. Zabezpieczenie
zostało w kodzie (zamyka realną lukę, a błąd, przed którym chroni, zatrzymuje układ), ale jeśli liczniki dalej
będą zerowe, jest do usunięcia.

Czasy wszystkich awarii od startu hosta (P4 startuje ok. 2 s przed C6): ok. 60 s (cztery razy) i ok. 165 s (dwa
razy). Cyberdeck w tle próbuje połączyć się z zapamiętanym urządzeniem LE: pierwsza próba 20 s po starcie, potem
odstęp 5 s podwajany po każdej porażce do 60 s (`app/bt/bt_reconnect_model.h`), czyli próby ok. 20, 25, 35, 55–60,
95–100 i 155–165 s po starcie. Awarie padały przy tych próbach, które trafiły na pary Soft-BR; przy wcześniejszych
szły tylko sondy (jeden wolny element naraz) i nic się nie działo.

**Siódmy przebieg (21:30)**, zmiana: `le_guard_h2c()` w `br_c6_core.c`. Gdy silnik pracuje, polecenie hosta
włączające skan LE (`0x200C`, `0x2042`) albo zaczynające połączenie LE (`0x200D`, `0x2043`) dostaje odpowiedź
Command Disallowed i nie trafia do kontrolera; autotest nie zaczyna wyszukiwania, gdy host skanuje albo łączy.
Rekord `0xC2` pokazuje, ile takich poleceń przeszło i ile odmówiono.

| Co | Wynik |
|---|---|
| Rundy wyszukiwania (10,24 s każda) | 23 pod rząd, bez restartu C6 do końca próby (powrót strażnika) |
| Pary TX/RX | 94 044 slotów TX, 94 042 RX, pominięte 2, zatrzymane po czasie 2 |
| Głośnik | znaleziony w każdej rundzie; 117 dopasowań adresu dostępu, 112 pakietów FHS z poprawnym HEC i CRC, 0 z błędnym |
| Polecenia skanu LE hosta | 5 przepuszczonych (w przerwach między rundami), 10 odmówionych (w trakcie rund) |
| Sterta C6 | 107 kB wolne na początku i na końcu, najniżej 91 kB |
| Liczniki `controller_links()` | 0 |

Wniosek: awarię wyzwalał skan LE hosta uruchamiany w czasie, gdy w kolejce harmonogramu były pary Soft-BR. Co
dokładnie psuje wtedy kolejkę, nie jest ustalone; rozdzielenie na granicy HCI usuwa zderzenie. Nie obejmuje
istniejącego połączenia LE (zdarzenia połączenia też trafiają do kolejki) ani rozgłaszania; tego nikt nie
próbował. Dla produktu oznacza to regułę po stronie hosta: w czasie pracy Classic nie skanować i nie łączyć LE.

### 2026-11-10 (wieczór) — ósmy przebieg: wywołanie głośnika bez odpowiedzi; wzorzec z Windows

**Ósmy przebieg (21:38).** Autotest po pierwszym wyniku wyszukiwania przerywa je i wysyła do silnika
`HCI_Create_Connection` na znaleziony adres (pakiety jednoslotowe, przesunięcie zegara z odpowiedzi FHS, bez zamiany
ról); zdarzenia HCI silnika idą do śladu (`0xC3`), polecenia autotestu też (`0xC4`). Sloty czekające na pakiet ID
brały pakiety do 4 bajtów (`BR_RX_ID_MAX_LEN`).

| Co | Wynik |
|---|---|
| Wywołania | 23, wszystkie zakończone `Connection Complete` ze stanem 0x04 (page timeout) po 5,5 s |
| Odbiór w slotach odpowiedzi na wywołanie | nic: ani bajtów za adresem dostępu, ani znacznika czasu |
| Wyszukiwanie w tych samych rundach | głośnik znaleziony za każdym razem, FHS poprawne |
| Restarty C6 | 0 przez całą próbę (121 tys. par) |

**Wzorzec z komputera właściciela (Windows, karta Bluetooth Intel).** Komputer ma ten głośnik sparowany od marca
2026. Z zapisu Windows:

- LMP w wersji 12 (Bluetooth 5.3), producent układu 0x03E0; cechy LMP strony 0: `BF FE 8D FA DB BD 7B 87` — pakiety
  3- i 5-slotowe, szyfrowanie, zamiana ról, sniff, EDR 2 Mb/s (bez 3 Mb/s), przeplatany skan wyszukiwania i wywołań,
  AFH, Secure Simple Pairing, EIR, kontroler dwusystemowy (LE i BR/EDR);
- rekordy SDP: Audio Sink `0x110B` (AVDTP 1.3 na PSM `0x0019`, A2DP 1.3), Audio Source `0x110A`, AVRCP 1.6
  (kontroler i cel, AVCTP 1.4 na PSM `0x0017`), Handsfree 1.8 (RFCOMM 1), dwie usługi szeregowe producenta.

Dla `p4_bt_classic` wynika z tego: parowanie pójdzie przez Secure Simple Pairing (głośnik je ma, więc PIN nie
będzie użyty), strumień to A2DP 1.3 z SBC nad AVDTP 1.3. Na papierze stos ma wszystko, czego ten głośnik wymaga.

Próba połączenia z tego komputera o 21:44 (gniazdo RFCOMM na kanał 2, potem 1, bez wysyłania danych): brak
odpowiedzi głośnika na wywołanie (25 s bez połączenia, potem „sieć nieosiągalna” po 4,4 s). W tym samym czasie
głośnik odpowiadał na wyszukiwanie z Tab5. Wniosek: w chwili próby głośnik nie przyjmował połączeń od nikogo, więc
23 nieudane wywołania z Tab5 nie mówią jeszcze nic o naszym wywoływaniu ani o limicie długości odbioru. Właściciel
został poproszony o sprawdzenie, czy głośnik nie jest połączony z innym urządzeniem.

### 2026-11-10 (noc) — przebiegi dziewiąty do dwunastego: dlaczego głośnik nie odpowiada na wywołanie

Stan wyjściowy: w ósmym przebiegu głośnik był połączony z komputerem właściciela, więc tamte 23 nieudane wywołania
nic nie znaczyły. Od 21:49 głośnik jest wolny (właściciel usunął go z listy urządzeń komputera) i komputer łączy się
z nim za każdym razem: gniazdo RFCOMM na kanał 2 otwarte w 0,6–2,0 s, 66 razy na 66 prób między 21:49 a 22:18. To
jest wzorzec „głośnik przyjmuje połączenia”.

| Przebieg | Zmiana w obrazie | Wywołania z Tab5 | Odpowiedzi |
|---|---|---|---|
| 9 (21:46) | sloty czekające na ID na przemian z limitem długości 4 bajty i bez limitu (z czekaniem do 2,3 ms) | 21 | 0 |
| 10 (21:57) | czas szukania adresu dostępu liczony od startu elementu, nie od włączenia odbiornika | 24 | 0 |
| 11 (22:04) | ślad: kod dostępu i adres dla wyboru kanałów tak, jak liczy je układ | 23 | 0 |

Co te przebiegi wykluczyły:

- kod dostępu: wartość policzona w układzie zgadza się z algorytmem specyfikacji; ten sam algorytm przechodzi
  wektory wzorcowe specyfikacji dla LAP `000000`, `FFFFFF`, `9E8B33`, `9E8B34` (test czytnika), także dla adresów
  z zerowym najstarszym bitem LAP;
- wybór kanałów: tabele permutacji i wejścia jądra są takie same jak w libbtbb (`bluetooth_piconet.c`), a adres
  wejściowy policzony w układzie to `UAP[3:0]` i LAP głośnika;
- okno odbioru: po poprawce czasu szukania obejmuje cały slot.

W dziewiątym przebiegu C6 zresetował się raz w fazie sond (watchdog przerwań, ta sama pętla co wcześniej; 2 s
wcześniej host dostał zgodę na skan LE). Od tego przebiegu okna sond liczą się jako praca Soft-BR: skan LE hosta
jest wtedy odmawiany, a sondy nie startują, gdy host skanuje.

**Dwunasty przebieg (22:12): tylko nasłuch.** Obraz po pierwszym wyniku wyszukiwania przestaje nadawać i otwiera
okna 60 ms z adresem dostępu równym młodszym 32 bitom kodu dostępu głośnika, na częstotliwościach wywołania
i odpowiedzi dla kolejnych wartości X, na przemian z limitem długości i bez. W tym czasie komputer wywołuje głośnik
co kilka sekund (`pc_wywoluj.py`, 63 połączenia).

| Co odebrano | Wynik |
|---|---|
| Pakiety ID komputera na częstotliwościach wywołania, bez limitu | bajty `a6 5d 8e b1` (bity 32..63 słowa synchronizacji), stan `0x…10`, −46…−60 dBm |
| To samo z limitem 4 bajty | tylko pierwszy bajt `a6`, reszta zero; stan `0x…04`; znacznik czasu jest |
| Odpowiedzi ID głośnika na częstotliwościach odpowiedzi | te same bajty, słabsze (−64…−72 dBm), w obu trybach |
| Trafienia dla kolejnych X | serie po kilka kolejnych X (np. 1–7, 13–15), czyli ciąg komputera idzie po kanałach, które liczy nasze jądro |

Wnioski:

1. Odbiór pakietu ID z kodem głośnika działa w obu trybach. Z limitem długości modem oddaje znacznik czasu i jeden
   bajt, bez limitu czyta tyle bajtów, ile każe mu bit 40..47 słowa synchronizacji (tu 93).
2. Jądro wyboru kanałów jest poprawne także dla adresu głośnika: potwierdzone na żywym ruchu komputera.
3. Głośnik odpowiada komputerowi, a nam nie, przy tym samym kodzie i tych samych kanałach. Zostaje sam nadany
   pakiet. Po słowie synchronizacji komputer i głośnik milkną (w zapisie cztery bity naprzemienne i szum), a nasz
   pakiet ID ma za słowem synchronizacji 24 bity CRC, które modem BLE dokleja zawsze. Urządzenie w skanie
   wyszukiwania to toleruje (wyszukiwanie działa), urządzenie w skanie wywołań najwyraźniej nie.

Poprawka (w kodzie, testy hosta i `RESULT: PASS`): `br_air_build_id_tx(..., ends_with_sync, ...)`. Pakiet ID kończy
się ostatnim bitem słowa synchronizacji: bity 40..63 wychodzą jako CRC modemu, a wartość początkowa rejestru CRC
(`crc_preset` w żądaniu TX, `ls[9]` w adapterze) jest liczona wstecz dla każdego pakietu. Przełącznik
`id_ends_with_sync` (11. bajt komendy `BR_VS_SET_KNOBS`); autotest używa nowego pakietu w rundach nieparzystych,
starego w parzystych, dla wyszukiwania i dla wywołania tej samej rundy.

### 2026-11-10 (noc) — przebiegi trzynasty i czternasty: nie format pakietu ID i nie sam głośnik

| Przebieg | Co sprawdzał | Wynik |
|---|---|---|
| 13 (22:21) | pakiet ID kończący się słowem synchronizacji (rundy nieparzyste) i stary (parzyste), dla wyszukiwania i wywołania | wyszukiwanie znajduje głośnik w każdej rundzie obu rodzajów, czyli nowy pakiet jest poprawny w eterze (konwencje CRC modemu zgadnięte dobrze); wywołania: 22, odpowiedzi 0 w obu |
| 14 (22:29) | wywołanie na zmianę komputera właściciela (adres podany tylko przy budowaniu, `BR_ST_EXTRA_PEER`) i głośnika | bez odpowiedzi od obu |

Format pakietu ID nie jest więc przyczyną, a brak odpowiedzi nie dotyczy tylko głośnika: komputer, który zawsze
przyjmuje połączenia, też nie odpowiada na nasze wywołanie.

Trop z notatek obcego repozytorium (`radio_lab.c`, wpis 1.4.228): „a TX after an RX whose window runs past ~ls44
1028 is silently dropped” — nadanie ustawiane zbyt krótko po oknie odbioru modem pomija bez śladu. U nas silnik
kolejkuje następną parę po zgłoszeniu slotu RX. Przy wyszukiwaniu slot ma 500 µs i para idzie co 2,5 ms. Przy
wywołaniu slot ma 220 µs, para idzie co 1,25 ms (784 pary na sekundę w śladzie) i element TX zaczyna się ok. 0,2 ms
po końcu elementu RX. Liczniki pokazują wtedy „TX wykonane”, bo element wraca przez wywołanie zwrotne, ale nic nie
dowodzi, że pakiet wyszedł w eter. Hipoteza: większość pakietów wywołania nie jest nadawana.

Zmiana do sprawdzenia (w kodzie, `RESULT: PASS`): `BR_RX_MIN_US = 500` w `br_c6_radio.c` — żaden slot RX nie jest
krótszy niż 500 µs od granicy slotu, więc wywołanie idzie w rytmie wyszukiwania. Rzeczywisty minimalny odstęp
RX → TX nie jest zmierzony.

### 2026-11-10 (noc) — przebiegi piętnasty i szesnasty: wywołanie dostaje odpowiedź; stoi odpowiedź mastera (FHS)

**Piętnasty przebieg (22:37)**, `BR_RX_MIN_US = 500`: wywołanie idzie w rytmie wyszukiwania (ok. 400 par na
sekundę zamiast 784). Od pierwszej próby odpowiadają oba cele: komputer (pakiety ID z jego kodem, −48…−61 dBm)
i głośnik (−45…−68 dBm), po kilka razy w każdym wywołaniu, 43 µs po granicy slotu. Hipoteza z poprzedniego
punktu jest potwierdzona: przy parze co 1,25 ms pakiety wywołania nie wychodziły w eter, choć liczniki pokazywały
„TX wykonane”. Licznik `tx_done` adaptera nie jest więc dowodem nadania.

W trybie z limitem długości (4 bajty) modem oddaje z odpowiedzi jeden bajt i silnik jej nie przyjmuje
(`br_air_extract_rx` chce całej końcówki słowa synchronizacji), więc odpowiedzi ID są odtąd brane bez limitu.

**Szesnasty przebieg (22:45)**, liczniki uzgadniania w śladzie (`0xC5`, `br_engine_get_page_progress`):

| Co | Wynik (po 200 s próby, 11 wywołań: 6 komputera, 5 głośnika) |
|---|---|
| Odpowiedzi ID przyjęte przez silnik | 104 |
| Pakiety FHS wysłane w odpowiedzi mastera | 416 (cztery na odpowiedź: N = 2, 4, 6, 8) |
| FHS potwierdzone drugim pakietem ID | 0 |
| Pierwsze pakiety POLL | 0 |

Ani komputer (układ Intel), ani głośnik (Actions) nie potwierdzają naszego FHS. Co wiadomo o tym kroku:

- FHS wychodzi dwie ramki (2,5 ms) po pakiecie wywołania, czyli w drugim slocie mastera po odpowiedzi (N = 2),
  bo zgłoszenie slotu RX przychodzi za późno na slot następny. Specyfikacja każe urządzeniu czekać na FHS przez
  `pagerespTO` (8 slotów) i co 1,25 ms przechodzić na następną częstotliwość, więc N = 2 powinno być przyjęte, ale
  nie jest to sprawdzone na żadnym urządzeniu. Obcy projekt wysyła FHS zawsze w pierwszym slocie (N = 1).
- Budowa FHS (kod dostępu urządzenia wywoływanego, nagłówek z `LT_ADDR` 0, HEC i CRC z UAP urządzenia
  wywoływanego, wybielanie `0x60 | X`, pola ładunku) jest zgodna ze specyfikacją na tyle, na ile dało się to
  sprawdzić czytaniem; dekoder tych samych pól działa na FHS głośnika z odpowiedzi na wyszukiwanie.
- Odstęp wstawienie → start elementu TX dla FHS wynosi ok. 0,8–1,1 ms, jak przy wyszukiwaniu.

Następne kroki, w kolejności:

1. Wzorzec z eteru: w trybie nasłuchu złapać FHS, który komputer wysyła głośnikowi (ten sam kod dostępu, kanał
   `f(X + 1)`), i zdekodować go naszym dekoderem z ziarnem `0x60 | (X + 1)` i UAP głośnika. Zgodność potwierdzi
   konwencje naszego kodera; niezgodność pokaże, która jest zła.
2. FHS w pierwszym slocie (N = 1): wymaga zgłoszenia odpowiedzi ID zaraz po jej odebraniu (nie po końcu slotu)
   i zmierzenia najmniejszego odstępu wstawienie → start, przy którym modem jeszcze nadaje.
3. Dopiero potem POLL/NULL na nowym połączeniu i stos hosta na P4 (LMP, parowanie, AVDTP, SBC) w odtwarzaczu.

### 2026-11-10 (noc) — przebieg siedemnasty: połączenie działa; przyczyną był HEC i CRC liczone ze złym UAP

Zamiast kolejnych wariantów na sprzęcie: porównanie kodu z oficjalnym tekstem specyfikacji (Core 5.4, Vol 2
Part B rozdz. 2.4.4, 2.6.4, 6.5.1.4, 7, 8.3.3, dodatek B) i z jej danymi wzorcowymi (Vol 2 Part G).

Co mówi specyfikacja o kroku, na którym staliśmy:

- Urządzenie wywoływane po swojej odpowiedzi ID słucha FHS przez `pagerespTO` = 8 slotów i co 1,25 ms bierze
  następną częstotliwość sekwencji wywołania. FHS przy N = 2 i N = 4 jest więc dozwolony; N = 6 i 8 trafiają już
  w urządzenie, które wróciło do nasłuchu wywołań.
- FHS: kod dostępu urządzenia wywoływanego, `LT_ADDR` nagłówka 0, HEC i CRC inicjowane UAP urządzenia wywoływanego,
  wybielanie od `0x60 | X` (X z procedury odpowiedzi, czyli zamrożone X + N), zegar w ładunku próbkowany na
  początku nadawania i odświeżany przy każdym powtórzeniu.

Przyczyna: `br_hec_compute` i `br_crc16_compute` ładowały UAP do rejestru odwrócony bitowo (HEC) i do złej połowy
rejestru (CRC). Specyfikacja (7.1.1, 7.1.2): UAP_0 do pozycji 0, UAP_7 do pozycji 7; w CRC osiem „lewych” pozycji
to pozycje 0..7. Przy UAP = 0 obie wersje dają to samo — dlatego FHS z odpowiedzi na wyszukiwanie (HEC i CRC od
DCI = 0) dekodował się czysto, a nasz FHS (UAP urządzenia wywoływanego) odrzucało każde urządzenie. Testy hosta
tego nie widziały, bo sprawdzały koder dekoderem z tej samej biblioteki.

Dowód przed i po:

- test `test_official_sample_data` (`br_ll/test/test_air_hop.c`) na danych wzorcowych: przed poprawką HEC danych
  0x123 z UAP 0x47 = 0x65 zamiast 0x06; po poprawce zgadza się 20 wierszy HEC z 54-bitowymi nagłówkami, CRC
  (`6d d2`), sekwencja wybielania, słowa kodowe FEC 2/3 i kompletny pakiet DM1 z rozdziału 6.2;
- test `test_official_hop_sample_data`: ciąg wywołania, częstotliwości odpowiedzi, podstan odpowiedzi mastera
  dla N = 1..7 i 160 skoków połączenia (drugi zestaw, ULAP 0x2a96ef25) zgadzały się od razu;
- sprzęt, przebieg 17 (obraz z samą poprawką HEC/CRC, komputer jako drugie urządzenie): 51 odpowiedzi ID,
  166 FHS, 13 potwierdzeń w chwili ostatniego zapisu licznika, **14 razy `Connection Complete` ze stanem 0**
  (9 z komputerem, 5 z głośnikiem), 9 razy upływ czasu wywołania. Strażnik wrócił do 1.4.85.

Ten sam wzorzec w dalszych warstwach (dane wzorcowe Vol 2 Part G, rozdz. 1.1, 7.1, 7.2, 10.1, 10.5) — żadna
z tych funkcji nie była dotąd na antenie:

- `br_ssp_f1`, `br_ssp_f2_btlk`, `br_ssp_f3` brały młodszą połowę HMAC-SHA-256; specyfikacja dzieli przez 2^128,
  czyli bierze starszą. `br_ssp_g` była dobra.
- skrót E1/E3 łączył rozszerzony adres albo COF na przemian XOR i dodawaniem; specyfikacja dodaje bajtowo
  mod 256 we wszystkich szesnastu pozycjach. Przy adresie z samych zer wynik był ten sam.
- E0 miało własną inicjalizację rejestrów; napisane od nowa według rozdz. 4.4–4.6 (rozkład wejść z rysunku 4.5,
  zamykanie sprzężeń, rejestry mieszające od t = 39, 200 symboli, ładowanie równoległe bez aktualizacji rejestrów
  mieszających) i sprawdzone taktem po takcie na śladach wzorcowych: wszystkie cztery zestawy, po 120 bitów.
- ECDH P-192 w `p4_bt_classic` zgadza się z trzema zestawami wzorcowymi (dopisany test, kod bez zmian).

Stan: `sh br_ll/test/run.sh` ALL PASS, symulacja PASS, `p4_bt_classic/test/host` ALL PASS, obraz C6
(`RESULT: PASS`, 23:27) i `examples/tab5_player/build/tab5_player.bin` (23:26) zbudowane z tymi poprawkami.
Nie sprawdzone: redukcja klucza `br_crypto_kc_prime` dla długości innej niż 16 bajtów, E21/E22 poza jednym
wektorem, wszystko powyżej pasma podstawowego na antenie.

Uwagi na później, bez wpływu na następny krok:

- Tylko co czwarta odpowiedź ID kończy się potwierdzonym FHS. Specyfikacja każe wysłać FHS w slocie zaraz po
  odpowiedzi (N = 1); my zaczynamy od N = 2, bo raport odbioru przychodzi za późno. Gdyby wywołanie z odtwarzacza
  było zawodne, to jest pierwsze miejsce do poprawy.
- Powtórzenia FHS dla N = 6 i 8 są poza `pagerespTO`; można je obciąć do 4 ramek.

Następny krok: próba dźwięku (`proba.py … dzwiek`), właściciel przy ekranie: Scan / Pair, głośnik, Play;
potem `/sd/tab5_player.log`.

### 2026-11-10/11 (noc) — próby dźwięku 1–6 i przebiegi radiowe 19–22: stos dochodzi do strumienia

Właściciel przy ekranie, `proba.py … dzwiek`, odtwarzacz `examples/tab5_player` na P4. Każda próba kończyła się
inaczej; każda przyczyna poniżej ma pomiar.

| próba | jak daleko | co ją zatrzymało | dowód |
|---|---|---|---|
| dźwięk 1 (23:31) | parowanie SSP, szyfrowanie włączone, SDP stoi 7 s | E0 liczone bit po bicie zajmowało zadanie warstwy łącza C6; host (esp_hosted) zrestartował P4 | po przepisaniu E0 SDP przechodzi w 0,3 s |
| dźwięk 2 (23:46) | AVDTP gotowe, start strumienia, głośnik mówi „Bluetooth is connected" | C6: watchdog przerwań w `r_ble_lll_sched_check_remaining_entries` (z `r_ble_phy_isr`) po pierwszym DH3 | zapis awarii w NVS, adresy rozwiązane w ELF |
| dźwięk 3 (00:29) | strumień, bez restartu | głośnik nie potwierdza DH3, po 4 s rozłączenie 0x08 | dziennik odtwarzacza |
| dźwięk 4 (00:41) | AVDTP gotowe | drugie dotknięcie wiersza na liście rozłączyło gotowe połączenie (0x16) | dziennik: rozłączenie 8 ms po `AVDTP READY` |
| dźwięk 5, 6 (00:50, 00:59) | głośnik przyjął `LMP_max_slot_req` (3 sloty), strumień | jak w 3: od pierwszego DH3 nie słychać głośnika wcale | liczniki C6 co sekundę: `sync` stoi na 307, `resent` rośnie o 200/s |

Zmierzone na C6:

- E0 w wersji bajtowej (rekord `0xC6`): 368–381 µs dla pakietu 30-bajtowego, 977–995 µs dla 340 bajtów; pierwsze
  bajty zgodne z danymi wzorcowymi także na układzie. Wersja bitowa była na PC 4,8× wolniejsza.
- Czas od wyboru slotu do oddania pary (rekord `0xC7`): do 690 µs dla pakietów bez szyfru, 1670 µs dla DH3
  z szyfrem. Silnik zostawiał na to 110 µs.
- Przebieg 20, celowo spóźnione pary z elementem TX długości DH3 (kontrola adaptera wyłączona na czas testu):
  100 µs i 500 µs po starcie bez widocznej szkody; po parze spóźnionej o 1000 µs układ zawiesił się w ciągu ok. 8 s
  w tej samej pętli co w próbie dźwięku 2. Test usunięty z obrazu po odpowiedzi.
- Przebiegi 21 i 22, sonda danych na połączeniach autotestu (rekord `0xC8`; echo L2CAP, bez LMP): ramka 20 bajtów
  w jednym DH1 potwierdzana od razu przez komputer i głośnik; fragmenty 27-bajtowe komputer odrzuca (NAK) około
  400 razy na jeden przyjęty; DH3 164 bajty komputer odrzuca zawsze, głośnik na DH3 nie odpowiada (na tych
  połączeniach nikt nie pozwolił na pakiety wieloslotowe). Nagłówki odpowiedzi słyszymy poprawnie.
- Przebieg 22, przełącznik „dewiacja skalowana do Classic" (`br_c6_set_gauss_bt05`, współczynniki pod
  0x600A20E0 × 0,64): w 12 rundach z przełącznikiem komputer nie dał ani jednej odpowiedzi ID, w 11 rundach bez
  niego 10 połączeń. Przełącznik zostaje wyłączony; czy psuje nadajnik, czy odbiornik — nie wiadomo.
- Po poprawce czasu budowy FHS jest potwierdzany za pierwszym razem (10 z 10 w przebiegu 22; wcześniej ok. 1 na 3
  odpowiedzi ID, bo para z FHS bywała oddawana po czasie).

Co mówi specyfikacja i co poprawiono:

- LMP 4.1.10: po nowym połączeniu wolno używać pakietów 1-slotowych; więcej dopiero, gdy druga strona wyśle
  `LMP_max_slot` albo przyjmie `LMP_max_slot_req`, a te PDU „can be sent at any time after connection setup is
  completed". Host prosił z pierwszymi PDU zestawiania, a silnik używał DH3 bez względu na odpowiedź. Teraz:
  prośba w `finish_setup`, `LMP_max_slot` od głośnika honorowane, wynik idzie do kontrolera komendą
  `BR_VS_SET_TX_SLOTS` (silnik: `tx_max_slots`, 1 po każdym nowym połączeniu) i do dziennika.
- Pasmo podstawowe 2.6.4.7, mechanizm tego samego kanału w AFH: „the Peripheral responds with its packet on the
  same RF channel that was used by the Central to address that Peripheral". Silnik brał dla slotu odpowiedzi
  kanał slotu mastera tuż przed nim, co po pakiecie 3-slotowym jest innym kanałem; host włącza AFH w chwili
  `AVDTP READY`, więc od startu strumienia odpowiedzi na DH3 szły tam, gdzie nie słuchaliśmy. Poprawka:
  `ch_rx = ch_tx`, gdy AFH jest włączone. Model głośnika w symulatorze miał ten sam błąd (dlatego symulacja
  przechodziła); z modelem zgodnym ze specyfikacją symulacja starego silnika staje, nowego przechodzi.
- Radio 3.1: indeks modulacji Classic 0,28–0,35; modem LE nadaje z ok. 0,5. To jest niezgodność, której nie
  umiemy na razie usunąć (patrz przełącznik wyżej) i najbardziej prawdopodobny powód odrzucania długich ładunków
  bez FEC. Nie jest to udowodnione.
- Silnik: `pair_built_in_time` (czas budowy wliczany w wybór slotu, spóźniona para nie jest oddawana), adapter:
  element startujący za mniej niż 40 µs nie trafia do planisty.
- Odtwarzacz: zapis dziennika przed restartem programowym, liczniki `BR_VS_GET_DIAG` co sekundę, drugie
  dotknięcie połączonego głośnika nie rozłącza, bitpool 18 (trzy ramki z nagłówkami = 164 bajty = jeden DH3 przy
  limicie 168), obraz wgrany na próbę sam wraca do poprzedniego firmware po 15 minutach bezczynności.

Stan testów: `br_ll/test/run.sh` ALL PASS, symulacja PASS, `p4_bt_classic/test/host` ALL PASS (uruchamiać
`build/test_bt_classic.exe`), `tools/tests` 90 testów, skan prywatności 0 trafień.

Nie wiadomo jeszcze:

- czy głośnik potwierdza DH3, gdy słuchamy na właściwym kanale (próba dźwięku 7);
- gdzie między 20 a 27 bajtami zaczyna się odrzucanie ładunku DH1 (sonda ma teraz ramki 23, 25, 27 bajtów);
- jak ustawić dewiację nadajnika zgodną z Classic.

Jeżeli DH3 okaże się nieużywalny na tym modemie: strumień pakietami 1-slotowymi z FEC (DM1, 17 bajtów) albo
krótkimi DH1 wymaga wysyłania pary co 1,25 ms zamiast co 2,5 ms (następny pakiet przygotowany przed raportem
z odbioru) i niskiego bitpoola; obcy projekt gra tak przy bitpoolu 14.

### 2026-11-11 (noc) — przebiegi 23 i 24: gdzie kończy się pewny pakiet i co silnik robi, gdy go przekroczy

Próba dźwięku 7 (01:50) nie doszła do skutku: nikogo nie było przy ekranie, głośnik był wyłączony (skan: 0
urządzeń). Odtwarzacz po 15 minutach bezczynności sam wrócił do Cyberdecka — bezpiecznik zadziałał na sprzęcie.

Przebieg 23, drabinka długości z komputerem (po 6 prób, każda do ok. 1600 transmisji, bez LMP):

| ramka w jednym pakiecie | dostarczona | odrzuceń przed sukcesem |
|---|---|---|
| 20 bajtów, DH1 (kontrolna, 23 razy) | zawsze | 0–5 |
| 23 bajty, DH1 | 5 z 6 | 188–1353 |
| 25 bajtów, DH1 | 3 z 6 | 2–986 |
| 27 bajtów, DH1 | 1 z 6 | 173 |
| 164 bajty, DH3 | 0 z 6 | – |

Nagłówek słyszany jest zawsze; odrzucany jest ładunek. Granica leży między pakietem trwającym 310 µs (20 bajtów)
a 334 µs (23 bajty). FHS (366 µs, FEC 2/3) w tym samym przebiegu przechodzi za pierwszym razem, więc to nie jest
proste obcięcie nadawania po czasie; przyczyna nie jest znana. Kandydaci, żaden nie sprawdzony: indeks modulacji
LE zamiast Classic (odbiornik w stanie połączenia gubi się na dłuższym ładunku), coś w modemie około 376 µs od
początku ramki LE. Komputer bez LMP nie jest też zwykłym odbiorcą: przy ramce z wielu fragmentów odrzuca dużo
więcej (bufor).

Wniosek dla silnika, zgodny ze specyfikacją (pasmo podstawowe 7.6.2.2 i 7.6.3): pakiet danych, którego druga
strona nie potwierdza w 16 transmisjach, jest porzucany — zastępuje go pakiet kontynuacji ACL-U o długości zero
z tym samym SEQN, po jego potwierdzeniu ramka zaczyna się od nowa w mniejszych pakietach (poziomy: to, na co
pozwala druga strona → jeden slot do 27 bajtów → jeden slot do 20 bajtów). Poziom tylko maleje i tylko w obrębie
połączenia (`step_down_after_silence`, `tx_size_level`; w dzienniku odtwarzacza `size ...`, `flush(es)`).

- symulator: głośnik, który pozwala na pakiety 3-slotowe i na żaden nie odpowiada (`sim_br no-3-slot`): stary
  silnik staje, nowy dostarcza 40 z 40 ramek pakietami 1-slotowymi (75,6 kb/s); zwykły przebieg bez zmian
  (278 kb/s);
- sprzęt, przebieg 24: ramki 23, 25, 27 i 164 bajty dostarczone w 21 próbach z 21 (wcześniej odpowiednio 5, 3, 1
  i 0 z 6); komputer potwierdza pakiet o długości zero i przyjmuje ramkę zaczętą od nowa.

Co to znaczy dla dźwięku: jeżeli głośnik potwierdzi DH3 (teraz słuchamy odpowiedzi na właściwym kanale), strumień
przy bitpoolu 18 mieści się z zapasem. Jeżeli nie, łącze zejdzie samo na pakiety 20-bajtowe: 20 bajtów co 2,5 ms
to 64 kb/s, za mało na SBC 44,1 kHz stereo (bitpool 18 potrzebuje ok. 140 kb/s) — dźwięk będzie, ale rwany.
Płynny dźwięk w tym wariancie wymaga wysyłania pary co 1,25 ms (następny pakiet gotowy przed raportem z odbioru)
albo usunięcia przyczyny, dla której dłuższe pakiety są odrzucane.

Zbudowane z tym wszystkim: `c6_firmware/build_guardtest/network_adapter.bin` (02:33, `RESULT: PASS`, bez
dodatkowego urządzenia) i `examples/tab5_player/build/tab5_player.bin` (02:33).

### 2026-11-11 (rano) — próba dźwięku 8: pierwszy dźwięk z głośnika, trzy straty przepustowości

Obrazy z 02:33, właściciel przy ekranie, głośnik włączony. Głośnik gra, ale „strasznie nieczytelnie i strasznie
zacina". Liczniki kontrolera z dziennika odtwarzacza (co sekundę, 196 s połączenia):

| okres | pary/s | z odpowiedzią | ramek dźwięku/s (potrzeba 115) | LMP nadane/s | LMP odebrane/s |
|---|---|---|---|---|---|
| pierwsze 9 s strumienia | 215 | 72 % | 73–83 | 74–87 | 37–44 |
| reszta (184 s) | 375 | 61 % | 12–14 | 110–119 | 55–60 |

Co z tego wynika:

- **Pakiety 3-slotowe działają z głośnikiem.** Przez pierwsze 9 s każda ramka (164 bajty) szła jednym DH3 i była
  potwierdzana — poprawka kanału odpowiedzi przy AFH (próba 6 → 7) jest potwierdzona na sprzęcie. Odmowy długich
  pakietów przez komputer w przebiegach 21–24 nie przenoszą się na głośnik z zestawionym LMP.
- **Pętla LMP zabierała połowę łącza.** Przez całe połączenie szły dwa PDU LMP na każde jedno odebrane (stosunek
  2,00), z częstością ograniczoną tylko tempem łącza. Jedyna prośba, na którą stos odpowiadał dwoma PDU, to
  `LMP_max_slot_req` dla więcej niż jednego slotu: `LMP_not_accepted` i do tego `LMP_max_slot 1`. Specyfikacja
  (LMP 4.1.10, sekwencja 20) przewiduje samo `LMP_not_accepted`; dodatkowe `LMP_max_slot` głośnik kwitował
  ponowną prośbą. Poprawione w `btc_lmp.cpp`, test `test_lmp_requests_from_the_peer_get_one_answer`. Przy okazji
  tej samej tabeli: `LMP_SUPERVISION_TIMEOUT` miał numer 31, który należy do `LMP_incr_power_req` (właściwy: 55);
  prośby o zmianę mocy dostają teraz `LMP_max_power` / `LMP_min_power` (LMP 4.1.3), a `LMP_auto_rate`
  i `LMP_preferred_rate` — nic, bo o nic nie proszą. Że w pętli chodziło o `LMP_max_slot_req`, wynika ze
  stosunku 2:1 i z kodu; dziennik próby 8 nie zapisywał kodów PDU (następny zapisuje).
- **Zejście na krótkie pakiety było fałszywe.** Po 9 s łącze przeszło na pakiety 20-bajtowe (9 pakietów na ramkę)
  i zostało tam: 13 ramek/s zamiast 115. W tej sekundzie nie było więcej powtórzeń niż zwykle, czyli nie było
  16 prawdziwych nieudanych transmisji z rzędu. Stara reguła liczyła każde wywołanie budowy retransmisji, także
  wtedy, gdy para w ogóle nie poszła w eter. Symulator pokazuje to wprost: po 40 parach odrzuconych przez radio
  (`sim_br busy-radio`) i po 400 ms ciszy (`sim_br outage`) stary silnik schodził na stałe, mimo że głośnik
  przyjmuje DH3. Co dokładnie zaszło w 137. sekundzie, nie wiadomo — koniec wiersza dziennika (poziom rozmiaru)
  był obcięty na 256 znakach.
- **28–39 % par zostaje bez odpowiedzi**, niezależnie od długości pakietu (przy DH3 mniej niż przy 1-slotowych).
  Przyczyna nieznana; następny dziennik pokazuje odsetek odpowiedzi na każdym z 79 kanałów.

Nowa reguła rezygnacji z rozmiaru pakietu (`size_evidence` w `br_engine.c`):

- liczą się tylko transmisje, które były w eterze, i tylko gdy głośnik nie zgłasza STOP;
- po 12 takich transmisjach bez potwierdzenia silnik sprawdza, czy druga strona w ogóle słucha: wyraźny NAK na
  ostatnią to potwierdza, w przeciwnym razie w miejsce pakietu idzie jeden POLL (pasmo podstawowe 6.5.1.3: POLL
  wymaga odpowiedzi i nie zmienia ARQN ani SEQN). Odpowiedź = „uderzenie" przeciw klasie rozmiaru; cisza = łącze
  leży, runda zaczyna się od nowa;
- pakiet tej klasy potwierdzony we własnej parze kasuje uderzenia; dwa z rzędu obniżają poziom, a ramka w locie
  jest porzucana jak dotąd (7.6.2.2);
- potwierdzenie liczy się tylko jako odpowiedź na sam pakiet, nie na POLL wysłany w jego miejsce (głośnik, który
  wbrew regule potwierdza każdy POLL, nie może „potwierdzić" pakietu, którego nie odebrał —
  `sim_br no-3-slot-poll-ack`).

Model głośnika w symulatorze ustawiał ACK przy każdym POLL; teraz ustawia ARQN według 7.6.1 (NAK po slocie bez
kodu dostępu, POLL niczego nie zmienia).

Dziennik odtwarzacza: wiersz liczników podzielony na dwa (`C6 link:` i `C6 size:` — poziom, porzucone ramki,
uderzenia, POLL-e kontrolne, pary odrzucone przez radio, najdłuższa cisza w parach), `LMP (opcode x count):` co
sekundę, `C6 chan:` co 10 s (79 znaków, dziesiąte części par z odpowiedzią; nowa komenda
`BR_VS_GET_CHAN_STATS`). Bufor wiersza w `log_sink.cpp` 256 → 384 znaki. Skrypt
`cd-rel/local/proba-2026-11-10/link_rates.py` liczy z tego tempa.

Rachunek dla następnej próby: para z DH3 trwa 5 ms (budowa zaszyfrowanego pakietu do 1,7 ms), czyli 200 par/s;
przy 28 % strat 144 ramki/s na potrzebne 115. Bez pętli LMP i bez fałszywego zejścia dźwięk powinien być ciągły;
zapas wynosi 25 % i znika przy stratach powyżej 42 %.

Stan testów: `br_ll/test/run.sh` ALL PASS; symulacja w pięciu wariantach PASS (zwykły 278 kb/s, `no-3-slot`
73,6, `no-3-slot-poll-ack` 73,6, `outage` 134, `busy-radio` 231); `p4_bt_classic/test/host` ALL PASS;
`tools/tests` 90 testów.

### 2026-11-11 07:50 — próba dźwięku 9: głośnik nie połączony, zabrakło czasu próby

Obrazy z 07:30 (poprawki po próbie 8). Poprawek nie udało się sprawdzić: do strumienia nie doszło.

Przebieg według dziennika odtwarzacza (czas od startu odtwarzacza): skan przy starcie znalazł głośnik (11 s);
pierwsze dotknięcie głośnika dopiero w 277. sekundzie; dwa wywołania (277 s i 314 s) skończyły się po 5 s
przekroczeniem czasu (status 0x04); trzy skany w 338–365 s nie znalazły nic; w 374–389 s głośnik był znów
widoczny (dwa krótkie połączenia skanu po nazwę doszły do skutku); czwarte łączenie w 391 s przerwał powrót C6
do potwierdzonego firmware w 397 s (koniec 420 s próby strażnika), po czym P4 sam wrócił do Cyberdecka.

Wnioski:

- okno 420 s jest za krótkie na próbę z człowiekiem: instalacja odtwarzacza zabiera z niego 130 s. Obraz testowy
  budowany z `BR_ST_TRIAL_SECS=900` (środowisko `build.sh`, 420–1800) wraca po 15 minutach; bez tej zmiennej jak
  dotąd po 420 s (przebiegi radiowe). `proba.py dzwiek` liczy czas dla 900 s;
- jedno wywołanie nie zawsze trafia w głośnik (przy stracie ok. jednej trzeciej wymian na tym radiu): host
  ponawia je do trzech razy (`connect_internal`, do ok. 20 s na jedno dotknięcie);
- między 277. a 365. sekundą głośnik nie odpowiadał ani na wywołania, ani na zapytania; czy wyszedł wtedy z trybu
  parowania, nie wiadomo. Głośnik włączać w tryb parowania dopiero, gdy odtwarzacz jest na ekranie.

Nowe wiersze dziennika (`C6 link:`, `C6 size:`, `LMP (opcode x count):`, `C6 chan:`) zapisały się w całości przy
krótkich połączeniach skanu.

### 2026-11-11 08:07 — próba dźwięku 10: bez pętli LMP głośnik przechodzi na pakiety, których C6 nie odbiera

Obraz C6 z oknem 900 s, odtwarzacz z ponawianiem wywołania. Pierwsze wywołanie bez odpowiedzi, drugie udane
(ponawianie zadziałało), parowanie i szyfrowanie przeszły w 1,5 s. Dziennik po raz pierwszy pokazuje kody LMP:

- głośnik wysłał `LMP_max_slot_req` (46) **raz**, dostał jedno `LMP_not_accepted` (4) i więcej nie pytał — pętla
  z próby 8 to była ta prośba, a napędzało ją nasze `LMP_max_slot 1` po każdej odmowie (teraz potwierdzone
  zapisem, nie tylko stosunkiem 2:1);
- zaraz po tym, jak głośnik przyjął nasze `LMP_max_slot_req` (3 sloty dla nas), jego pakiety zaczęły przychodzić
  z błędnym CRC: 47–50 na sekundę przez 10 s, przy poprawnych nagłówkach i bez żadnego naszego pakietu w locie
  (`acked` i `resent` stoją). Host czekał na odpowiedź SDP/AVDTP i po 12 s zerwał („Timed out waiting for AVDTP
  Media open"). Głośnik powtarzał w kółko jeden pakiet, którego 1-slotowe okno odbioru C6 (46 bajtów) nie mieści,
  czyli przeszedł na pakiety wieloslotowe. Typu pakietu dziennik nie zapisuje — to wniosek z długości okna
  i z tego, że w próbie 8, z ciągłym `LMP_max_slot 1`, te same odpowiedzi przychodziły poprawnie.

Dlaczego głośnik uznał, że wolno mu nadawać dłuższe pakiety, nie wiadomo (odmowa potraktowana jak zgoda albo
nasza prośba o 3 sloty potraktowana jako zgoda w obie strony). Poprawka nie zależy od tego, która z tych rzeczy
zaszła — odtwarza warunki próby 8 w tempie, które nic nie kosztuje (`btc_lmp.cpp`):

- prośba głośnika czeka na `btc_lmp_on_tick` (co 0,5 s z zadania zdarzeń hosta) i dostaje wtedy
  `LMP_not_accepted` oraz `LMP_max_slot 1`;
- po odpowiedzi głośnika na naszą prośbę (zgoda albo odmowa) od razu idzie `LMP_max_slot 1`.

Ostatnie słowo, jakie głośnik ma od nas o swoich pakietach, to zawsze „jeden slot"; wymiana zamiast 50 razy na
sekundę biegnie najwyżej 2 razy (6 PDU/s). Test: `test_lmp_peer_stays_on_one_slot_without_a_loop`.

Inne liczby z tej próby: przy samych POLL-ach (67 par/s, nic w locie) odpowiedź przychodzi na 70–73 % par, na
wszystkich kanałach podobnie (`C6 chan:` 742 pary, cyfry 3–9 bez wyraźnego pasma) — strata ok. 30 % nie zależy
więc od długości pakietu ani od obciążenia i nie wygląda na zakłócenie jednego pasma Wi-Fi (router na kanale 4).
Najdłuższa cisza: 28 par z rzędu podczas włączania szyfrowania.

### 2026-11-11 08:29 — próba dźwięku 11: muzyka gra

Obraz C6 z 08:03 (okno 900 s), odtwarzacz z 08:16 (odpowiedź na `LMP_max_slot_req` w tempie 2/s). Właściciel przy
głośniku: „mamy muzykę, gra w miarę płynnie, ale mamy jakieś dropy i przerwania, zacięcia".

To jest pierwsza wersja, która odtwarza muzykę z Tab5 na głośniku Bluetooth Classic przez modem BLE układu C6.
Stan kodu z tej próby jest zapisany commitem i znacznikiem `tab5-classic-first-music-2026-11-11`; oba wgrane
obrazy (z plikami ELF i sumami SHA-256) leżą poza repozytorium w
`cd-rel/local/proba-2026-11-10/dziala-2026-11-11/`.

Jak odtworzyć: `BR_ST_TRIAL_SECS=900 sh c6_firmware/build.sh --guard-test`, `sh examples/tab5_player/build.sh`,
potem `python proba.py <host> dzwiek bez-hotspotu` w `cd-rel/local/proba-2026-11-10`; głośnik w tryb parowania
dopiero, gdy odtwarzacz jest na ekranie; Scan / Pair → głośnik (raz) → Play.

Zostaje: gubione ramki (zacięcia). Znane składniki: ok. 30 % par bez odpowiedzi i para z DH3 co 5 ms.

### 2026-11-11 — skąd zacięcia w próbie 11: przerwy w odpowiedziach głośnika, nie brak przepustowości

Liczby z dziennika próby 11 (263 s strumienia, `link_rates.py`):

- łącze przeniosło 113–115 ramek/s z potrzebnych 115; poziom rozmiaru cały czas „as allowed", 0 porzuconych
  ramek; odtwarzacz zgubił 347 pakietów z 27 345 (1,3 %, czyli 1,3 na sekundę);
- wymiana `LMP_max_slot_req` biegnie 1,9 raza na sekundę (495 próśb, 494 odmowy, 496 `LMP_max_slot 1`) i głośnik
  trzyma się pakietów 1-slotowych;
- **w każdej z 264 sekund jest seria co najmniej 8–9 par z rzędu bez odpowiedzi**, najczęściej 9 (84 s) albo 12–18;
  przy 30 % strat rozłożonych losowo taka seria trafiałaby się raz na kilka minut. Straty nie są więc losowe:
  łącze staje na 45–100 ms mniej więcej pięć razy na sekundę (ok. 51 powtórzeń/s w seriach po ok. 10 par).
  To samo widać w próbie 10 przy samych POLL-ach co 15 ms (serie 4–6 par, 27–30 % bez odpowiedzi) i w próbie 8;
  nie zależy od długości pakietu, obciążenia, wymiany LMP ani AFH, a rozkład po kanałach jest równy (6–7/10 na
  każdym). Źródło przerw nie jest znane: głośnik (np. skanowanie w trybie parowania) albo radio C6;
- 115 razy silnik wysłał kontrolny POLL po 12 transmisjach bez odpowiedzi, 30 razy głośnik na niego odpowiedział;
  nigdy dwa razy z rzędu dla tego samego pakietu, więc rozmiar pakietów nie spadł ani razu.

Skąd utrata ramek: kontroler trzyma 8 pakietów (70 ms dźwięku). Pakiet, który przy dłuższej przerwie nie znalazł
miejsca, był od razu wyrzucany, choć po przerwie łącze nadrabia (200 par/s przy 115 potrzebnych).

Poprawki (host, `p4_bt_classic`):

- `btc_media_queue.h`: 32 pakiety (279 ms) czekają po stronie P4 na miejsce w kontrolerze; zadanie strumienia
  ponawia co 2 ms, gdy coś czeka; przy pełnej kolejce ginie najstarszy pakiet;
- `btc_upper_send_media_packet` zwiększa numer sekwencyjny RTP i znacznik czasu dopiero, gdy pakiet wyszedł
  (dotąd przy każdej próbie — przy ponawianiu głośnik widziałby brakujące pakiety, których nie brakuje);
  pakiet porzucony liczy `btc_upper_skip_media_packet`;
- dziennik: `media queue: N waiting, most M, lost K`.

Pomiar źródła przerw (silnik): `br_engine_take_gaps` / `BR_VS_GET_GAPS` — każda seria co najmniej 3 par bez
odpowiedzi z chwilą początku i długością; host zapisuje co sekundę
`C6 gaps (ms since the one before + length (pairs)): ...`. Z odstępów między początkami wyjdzie, czy przerwy są
okresowe i z jakim okresem. Symulator (`sim_br outage`) sprawdza, że przerwa 400 ms jest zapisana z długością.

Czego ta poprawka nie załatwi: jeżeli bufor głośnika jest krótszy niż przerwa, zacięcie powstaje w głośniku, nie
u nas. Do tego potrzebne jest usunięcie samych przerw.

### 2026-11-11 09:00–10:00 — próby dźwięku 12 i 13, przebiegi radiowe 25 i 26: płynnie; dokąd sięga jakość

**Próba 12** (kolejka na P4, rejestr przerw): właściciel — „bardzo płynnie", ale „jakość jakby gorsza" niż
z telefonu i „drobne trzeszczenie". Dziennik: 0 utraconych pakietów (próba 11: 347), najwyżej 10 czekających
w kolejce, 114,8–115,3 ramek/s. Obrazy tej wersji i łata względem `f0d1581`:
`cd-rel/local/proba-2026-11-10/plynnie-2026-11-11/`.

Rejestr przerw (1044 przerwy w 248 s): długość najczęściej 40–60 ms (mediana 52 ms, najdłuższa 112 ms), odstępy
między początkami układają się w powtarzalny wzór ok. 160, 160, 320 ms — trzy przerwy w cyklu 640 ms, czwarta
pominięta. Tak zachowuje się urządzenie, które ma jedno radio i w stałym rytmie wychodzi z naszej pikosieci:
najprościej głośnik w trybie parowania, który dalej nasłuchuje wywołań i zapytań (page scan co 320 ms, inquiry
scan co 640 ms, okno ok. 45 ms). Tego nie sprawdzono innym pomiarem (np. czy głośnik podczas grania jest widoczny
dla telefonu), ale rytm w jednostkach slotów Classic (256 i 1024 sloty) wyklucza Wi-Fi (102,4 ms) i przypadek.
Te przerwy to ok. 30–35 % czasu łącza.

**Czas budowy pakietu.** Para z DH3 trwała 5 ms, bo zbudowanie zaszyfrowanego pakietu zajmowało do 1,7 ms
(dopuszczany zapas ok. 2050 µs). Przyczyny i poprawki:

- CRC, wybielanie i pakowanie były liczone bit po bicie, w kilku przejściach z 64-bitowymi przesunięciami:
  teraz tablice 256/128 pozycji i doklejanie bajtami (`br_air.c`);
- E0: rejestry 3 i 4 jako słowa 32-bitowe, początek bez 56 kroków jeden po drugim (pierwsze 25 bitów każdego
  strumienia wejściowego trafia do rejestru wprost, 15 kroków pojedynczo, reszta bajtami), układ sumujący po dwa
  kroki na odczyt tablicy (`br_crypto.c`);
- całe firmware C6 jest budowane z `-Og`; pięć plików silnika (`br_ll/*.c`) dostaje `-O2`
  (`c6_firmware/main/CMakeLists.txt`).

`br_ll/test/test_fast_paths.c` porównuje z kodem sprzed zmiany (commit `f0d1581`): CRC 3000 ładunków, wybielanie
ze wszystkich 128 stanów, 6000 losowych pakietów każdego typu zbudowanych i odczytanych, strumień E0 dla 400
losowych kluczy — cztery skróty FNV, te same na clang (Windows) i gcc (Linux). Pierwsza wersja testu zależała od
kolejności obliczania argumentów i dała różne liczby na obu kompilatorach; budowa w kontenerze to wykryła, razem
z `memcpy` o długości zero z pustego wskaźnika.

| pomiar | przed | po |
|---|---|---|
| PC (gcc -O2 -m32): zaszyfrowany DH3 164 B | 13,5 µs | 2,35 µs |
| C6, E0 dla 30 bajtów (przebieg 22 → 26) | 373 µs | 108 µs |
| C6, E0 dla 340 bajtów | 994 µs | 636 µs |
| C6, najdłuższa budowa pary bez szyfru | 690 µs | 360 µs |
| C6 w strumieniu, najdłuższa budowa / zapas (próba 12 → 13) | 3170 / ok. 2050 µs | 1150 / 612 µs |

Sam `-O2` dał na C6 niewiele (340 bajtów: 660 → 636 µs); koszt E0 to ok. 1,7 µs na bajt i nie wiadomo, dlaczego
tak dużo przy 160 MHz. Przebiegi 25 i 26: 8 i 13 połączeń zestawionych nowym kodem.

**Próba 13** (szybsza budowa, bitpool według łącza): „tak samo płynnie", 0 utraconych pakietów, najwyżej 3
w kolejce. Pary z danymi idą co 3,75 ms (192 pary/s przy łączu zajętym w 74 %). Bitpool został na 20, bo:

- przez pierwsze 160 s strumienia kontroler kończył 95 ramek L2CAP na sekundę, choć odtwarzacz robił 57,4
  pakietu audio, a od głośnika przychodziło 52 pakiety z CRC na sekundę (w próbach 11 i 12: ok. 2). Czyli ok.
  37 wymian L2CAP na sekundę poza dźwiękiem; ustały same w 185. sekundzie. Co to było, dziennik nie mówi.
  Łącze było przez to zajęte w 91 %;
- potem zajętość spadła do 74 %, a próg kroku w górę (przewidywane < 80 %) dawał 83 %.

Po tej próbie: dziennik zapisuje nagłówki pierwszych trzech ramek L2CAP od głośnika w każdej sekundzie
(`L2CAP rx: ...`); rejestracja powiadomienia AVRCP o stanie odtwarzania, które stos sam wymienia w
GetCapabilities, dostaje INTERIM zamiast odrzucenia (możliwa przyczyna wymiany — nie potwierdzona); próg 85 %.

**Bitpool według łącza** (`btc_rate.h`, zadanie strumienia w `btc_host.cpp`): konfiguracja AVDTP podaje
głośnikowi cały dozwolony zakres bitpooli (było: tylko wybrany), a strumień co 2 s mierzy, przez jaką część
czasu kontroler miał dane do wysłania (od oddania ramki przy pustym kontrolerze do zwrotu wszystkich kredytów).
Liczba ramek SBC w pakiecie audio jest dobierana tak, by pakiety DH3 po 168 bajtów były wypełnione (bitpool
18–20: 6 ramek w 2 DH3; 21–23: 8 w 3; 24–25: 5 w 2; 26–28: 7 w 3); bitpoole o tym samym koszcie są darmowe,
stąd start od 20. Krok w górę po trzech oknach z przewidywaną zajętością poniżej progu, krok w dół od razu przy
zgubionym pakiecie albo zajętości ponad 95 %.

Ile da się jeszcze wyciągnąć: przy parach co 3,75 ms i ok. 35 % nieobecności głośnika łącze mieści ok. 170 DH3
na sekundę; bitpool 23 potrzebuje 129, bitpool 25 — 138, bitpool 28 — 148. Limit DH3 183 bajty zamiast 168
(zapas na przełączenie nadawanie → odbiór spada z 309 do 189 µs) dałby bitpool 23 w cenie dzisiejszego 18.
Wyraźnie więcej wymaga, żeby głośnik przestał wychodzić z pikosieci (połączenie bez trybu parowania — nie
próbowane, potrzebny zapis klucza), bo modem BLE nie nadaje EDR ani pakietów 5-slotowych (ramka LE to najwyżej
255 bajtów).

Czy całość mogłaby działać na samym C6 (pytanie właściciela): na osobnej płytce tak, z dekoderem MP3 i koderem
SBC w arytmetyce stałoprzecinkowej (obecne są zmiennoprzecinkowe) — szacunkowo 50–70 % jedynego rdzenia, z czego
silnik radiowy 15–30 % (zmierzone). Na Tab5 nie (karta jest przy P4). Dla jakości nic by to nie dało: granice
są w eterze, a łącze P4–C6 nie jest wąskim gardłem (w kolejce najwyżej 3 pakiety); dołożenie dekodowania do
rdzenia, który ma 0,6 ms na zbudowanie pakietu, zwiększyłoby liczbę spóźnionych par.

### 2026-11-11 10:15 — próba dźwięku 14: bitpool 25, „gra dobrze"

Obraz C6 z 09:42 (silnik z `-O2`, okno 900 s), odtwarzacz z 09:58 (próg 85 %, dziennik `L2CAP rx:`, INTERIM dla
powiadomienia o stanie odtwarzania). Właściciel, patrząc na ekran odtwarzacza: po chwili bitpool 23 (59 bajtów
na ramkę), potem 63 bajty na ramkę (bitpool 25); „mam wrażenie, że jakość się poprawiała", „jest teraz
zdecydowanie lepiej z dźwiękiem, gra dobrze". W próbie 13 ten sam obraz C6 stał na bitpoolu 20, bo łącze
zajmowała dodatkowa wymiana L2CAP; czy tym razem jej nie było i czy pomogła odpowiedź INTERIM, pokaże dziennik
(w chwili zapisu tej wersji odtwarzacz jeszcze działał i dziennik nie był pobrany).

Stan kodu z tej próby: znacznik `tab5-classic-bitpool-25-2026-11-11`; obrazy, pliki ELF i sumy SHA-256 poza
repozytorium w `cd-rel/local/proba-2026-11-10/dobrze-2026-11-11/`.

Dla porównania: telefon z SBC używa zwykle bitpoola 53 (ok. 328 kb/s), „średnia jakość" A2DP to 35
(ok. 229 kb/s); bitpool 25 to ok. 174 kb/s.

### 2026-11-11 12:00–20:45 — Classic w Cyberdecku, zwykły obraz 1.5.0 na stałe, bezpiecznik awarii

Stos hosta i silnik zostały przeniesione do Cyberdecka (jego gałąź `wip/bt-classic`, opis i wszystkie próby:
`docs/specs/bt-classic-audio.md` tamże). Co z tych prób dotyczy tego repozytorium:

- **Classic gra przy działającym Wi-Fi** (odtwarzacz próbny nie miał sieci): 298 s, 0 utraconych pakietów,
  bitpool 25, każde z 298 zapytań HTTP do urządzenia z odpowiedzią (mediana 97 ms).
- **Łączenie zapisanym kluczem poza trybem parowania działa** (1–6 s do otwartego kanału audio). Przerwy w
  odpowiedziach głośnika są wtedy takie same (4,8 na sekundę, 26 % czasu): to nie skany trybu parowania, jak
  przypuszczano po próbie 12. Głośnik ma osobny kanał BLE i najpewniej dzieli między niego radio.
- **Wstrzymanie i wznowienie strumienia** (AVDTP SUSPEND po 5 s ciszy, START przy dźwięku) działa z X8 Pro.
- **Wywołanie Classic przy istniejącym połączeniu LE zawiesza C6** — dwa razy w jednej próbie (host zrestartowany
  przez sterownik SDIO). To przypadek, którego strażnik `le_guard_h2c` świadomie nie obejmuje („An LE connection
  that already exists is not covered"). Cyberdeck odmawia teraz takiej kolejności po swojej stronie; adapter C6
  nadal nie broni się sam — do zrobienia.
- **Bezpiecznik awarii był za surowy.** Te dwie awarie (sześć minut odstępu) wyłączyły Soft-BR w obrazie próbnym
  na stałe: po ponownym wgraniu tego samego obrazu host dostawał na 0xFC31 „nieznana komenda". Właściciel: po
  awarii i restarcie wszystko ma wracać do normy. Zmiana (`br_c6_crash.c`, test `test_br_c6_crash.c`): awarie
  w rekordzie są zapominane po `BR_CRASH_FORGIVE_SECS` (180 s) pracy bez kolejnej (`br_crash_forgive`, zapis
  w krótkim własnym zadaniu `br_ok`). Liczą się więc tylko dwie awarie jedna po drugiej, a wyłączony adapter
  wraca przy następnym starcie C6, bez nowego obrazu. Sam zapis po 180 s nie był jeszcze widziany na układzie
  (wykonuje się tylko po awarii).
- **Zwykły obraz** (`sh c6_firmware/build.sh`, bez autotestu i podsłuchu Wi-Fi, wersja 1.5.0) zbudowany z tą
  zmianą, `RESULT: PASS`, wgrany na Tab5 2026-11-11 20:31 i potwierdzony przez strażnika (zgłasza 1.5.0 po ponad
  10 minutach, czyli po czasie, w którym niepotwierdzony obraz zostałby cofnięty). Odpowiada na `BR_VS_PING`.
  Powrót: OTA obrazu 1.4.85 z publicznego modułu LE Audio.

### 2026-11-12 09:20 — „strasznie zacina": łącze utknęło na pakietach 1-slotowych; reguła rozmiaru pyta dwa razy i wraca

Zwykły obraz 1.5.0, Cyberdeck, właściciel słucha przez głośnik X8 Pro. Ok. 100 s po włączeniu tabletu: „strasznie
zacina". Po ponownym włączeniu tabletu gra dobrze. Liczniki łącza czytane co sekundę w obu przebiegach
(`/api/diag`, przyrosty na sekundę):

| | zły przebieg | po restarcie |
|---|---|---|
| poziom rozmiaru pakietów | 1 (jeden slot), 1 porzucona ramka | 0 (to, na co pozwala głośnik) |
| bitpool / zajętość łącza | 10 / 100 % | 23–25 / 82–88 % |
| pakiety dźwięku wysłane / utracone | 11–18 / 6–13 (35 % ginie) | 62–116 / 0 |
| pary / z odpowiedzią | 400 / 64–79 % | 195–240 / 60–75 % |
| ramki dostarczone głośnikowi | 14–17 | 67–71 |
| kontrolne POLL-e / uderzenia | 3–8 / ok. 0 | 1–4 / 1–3 |

**Dlaczego zacinało.** Na poziomie 1 para idzie co 2,5 ms i niesie do 27 bajtów: 300 potwierdzonych pakietów/s to
8,1 kB/s. SBC przy najniższym bitpoolu 10 potrzebuje 344,5 ramki/s × 33 B = 11,4 kB/s, z nagłówkami ok. 12,5 kB/s.
Łącze mieści więc ok. 65 % strumienia — i dokładnie tyle doszło (2307 pakietów wysłanych, 1239 utraconych). Poziom
rozmiaru tylko malał, więc tak zostawało do końca połączenia.

**Dlaczego poziom spadł.** Głośnik przyjmuje DH3 (140 potwierdzonych na sekundę w dobrym przebiegu). Ale w dobrym
przebiegu reguła z próby 8 liczy 1–3 „uderzenia" na sekundę: prawie każdy kontrolny POLL po 12 transmisjach bez
odpowiedzi dostaje odpowiedź. To zbieg długości: przerwy w odpowiedziach głośnika trwają najczęściej 40–60 ms
(mediana 52 ms, rejestr przerw z próby 12), a 12 transmisji DH3 co 3,75 ms trwa 45 ms — POLL wypada tuż po
powrocie głośnika. Odpowiedź znaczyła więc „głośnik wrócił", a była liczona jako „głośnik jest, a pakietu tej
wielkości nie bierze". Uderzenie kasuje potwierdzenie pakietu; dwa z rzędu obniżają poziom. Wystarczą dwie
przerwy jedna po drugiej z chwilą obecności między nimi (rejestr z próby 12 zna przerwy do 112 ms) — przy dwóch
uderzeniach na sekundę to kwestia czasu, tu 100 s. W próbie 11 (pakiety 1-slotowe, 12 transmisji = 30 ms)
głośnik odpowiedział na 30 ze 115 takich POLL-i; przy DH3 na ok. 80 %.

**Poprawka** (`size_evidence` w `br_engine.c`):

- odpowiedź po rundzie bez odpowiedzi mówi tylko, że druga strona jest. Dopiero następna, krótka runda
  (`BR_SIZE_CONFIRM_TRIES` = 4 transmisje, 15 ms) rozstrzyga: jeżeli i ona zostaje bez potwierdzenia, a druga
  strona znów odpowiada, to jest uderzenie przeciw rozmiarowi. Cisza na POLL kasuje podejrzenie. Głośnik, który
  naprawdę nie bierze DH3, traci je po 12 + 4 + 4 transmisjach i trzech POLL-ach (wcześniej 12 + 12 i dwóch);
- obniżony poziom nie jest na zawsze: po `BR_SIZE_HOLD_US` (2 s) silnik znów próbuje pełnego rozmiaru; każde
  kolejne niepowodzenie bez potwierdzonego pakietu wieloslotowego pomiędzy podwaja czekanie, do 32 s. Termin jest
  sprawdzany przed każdą parą (także przy samych POLL-ach), żeby długa cisza w danych nie zostawiła starego terminu
  za przewinięciem zegara mikrosekund.

Symulator (`br_ll/sim/run.sh`, trzy nowe warianty; na starym silniku wszystkie trzy padały):

- `slices` — dwie serie bez odpowiedzi jedna po drugiej, pierwsza kończy się na POLL-u silnika, głośnik przyjmuje
  DH3: stary silnik kończył na poziomie 1 z jedną porzuconą ramką (dokładnie stan z tabletu), nowy zostaje przy
  DH3 (263 kb/s);
- `3-slot-fade` — głośnik przez 500 ms nie bierze DH3: strumień idzie pakietami 1-slotowymi i wraca do DH3
  (ostatnie 40 ramek powyżej 200 kb/s; stary silnik: 77 kb/s do końca);
- `no-3-slot-long` — głośnik głuchy na DH3 przez 4 s strumienia: jedna ponowna próba pełnego rozmiaru, znów
  porzuconego, następna czeka dłużej; wszystkie ramki dostarczone (76 kb/s).

Stan: `br_ll/test/run.sh` ALL PASS, symulacja w ośmiu wariantach PASS, zwykły obraz **1.5.1**
(`sh c6_firmware/build.sh`, `RESULT: PASS`, skrót `b2bcabb3`). Licznik `size_strikes` w diagnostyce liczy teraz
tylko uderzenia po krótkiej rundzie; na sprzęcie powinien stać przy zerze przy niezmienionej liczbie POLL-i
kontrolnych — to jest sprawdzian poprawki.

**Na sprzęcie (2026-11-12 09:40–09:52).** Obraz 1.5.1 wgrany za zgodą właściciela (`c6_ota.py`, głośnik wcześniej
rozłączony), strażnik go potwierdził (1.5.1 przez 240 s obserwacji). Głośnik połączony zapisanym kluczem, właściciel
puścił muzykę: „gra płynnie". Pomiar 149 s strumienia: **412 kontrolnych POLL-i, 0 uderzeń** (na 1.5.0 było 1–3
uderzenia na sekundę), poziom rozmiaru 0, 0 porzuconych ramek, 9234 pakiety dźwięku wysłane i 0 utraconych,
bitpool 20–25 (mediana 25), zajętość 81 %, 67 % par z odpowiedzią (29 % w przerwach — bez zmian, to głośnik).
Nie widziane na sprzęcie: sam powrót z obniżonego poziomu (poziom nie spadł ani razu) — ten jest sprawdzony tylko
w symulatorze. Opis aplikacji w nagłówku obrazu mówi jeszcze „1.5.0" (CMake nie był konfigurowany od nowa po
zmianie pliku wersji); wersja zgłaszana przez wsad to 1.5.1.

### 2026-11-12 13:00 — czarna skrzynka w każdym obrazie (1.5.2)

**Powód.** 2026-11-12 między 10:49 a ok. 11:25 zwykły obraz (1.5.1, po cofnięciu także 1.5.0) restartował układ
w ciągu sekundy od pierwszego polecenia Classic hosta — kilka razy z rzędu, pod Cyberdeckiem, także przy samym
skanie. Potem przestał i nie dało się tego odtworzyć ani na obrazach testowych, ani na zwykłych (przebieg prób:
`docs/specs/classic-plus-le.md`, dziennik). Zwykły obraz nie zostawiał żadnego zapisu, więc przyczyna jest
nieznana. Zapis z 2026-11-11 (obraz testowy) mówił z kolei tylko „assert failed: osi_assert_wrapper bt.c:579":
zamknięty sterownik Bluetooth podaje numer wiersza i funkcję własnej asercji wyłącznie przez `ets_printf` w ROM
(„BLE assert: line N in function F, param: …”), tuż przed `assert(0)`, a tego nikt nie czytał.

**Co zapisuje** (`c6_firmware/main/br_c6_core.c`, „Black box”; w każdym obrazie, nie tylko testowym):

- obsługa paniki jest opakowana (`--wrap=esp_panic_handler`): w pamięci RTC, która przeżywa własny reset układu,
  zostaje rodzaj awarii, powód, nazwa zadania, pc, ra, sp, mcause, mtval i 24 słowa ze stosu wskazujące w kod
  (adresy powrotu wywołań prowadzących do paniki są wśród nich; stos trzyma też pozostałości wcześniejszych
  wywołań, dlatego 24, a nie kilka);
- drugi kanał wyjścia `printf` z ROM (`esp_rom_install_channel_putc(2, …)`; pierwszy to UART, którego w urządzeniu
  nikt nie czyta) prowadzi do pierścienia 96 znaków w tej samej pamięci — po asercji sterownika kończy się on jej
  wierszem;
- start po resecie z powodu awarii przenosi to do NVS (`br_c6` / `dump`, wersja 3; reset pinem przez hosta tej
  pamięci nie zachowuje, a host resetuje C6 dopiero po własnym restarcie, czyli po ok. 2 s);
- każdy start, gdy rusza Soft-BR, wpisuje do śladu `0xFC30/0x0A` rekord startu `0xBB` (powód resetu, czy Soft-BR
  pracował, licznik awarii, ile znaków ROM wypisał — dowód, że kanał działa) i, jeśli jest zapis, rekordy
  `0xBC`–`0xBE`, `0xC9`–`0xCB`. Host niczego nie musi zmieniać: Cyberdeck podaje ten ślad jako
  `GET /api/c6/cis/trace`.

**Odczyt:** `python tools/br_selftest.py HOST --box` — jeden odczyt śladu, wynik: start, zapis awarii, na końcu
złożony powód, ostatnie znaki ROM i lista adresów do `riscv32-esp-elf-addr2line -f -e <ELF obrazu, który padł>`.
Obraz, który znalazł zapis, jest nazwany pierwszymi bajtami skrótu ELF (rekord `0xC9`). Ślad trzyma 32 wpisy:
czytać przed zestawieniem LE Audio; sam zapis zostaje w C6 i wraca do śladu przy następnym starcie.

**Próba na układzie (2026-11-12 12:48–13:10, dwa obrazy testowe z opcją `BR_ST_CRASH_TEST=1`).** Obraz testowy
minutę po starcie robi raz to samo, co asercja sterownika: wiersz „BLE assert: line 1234 in function box_test,
param: 0xa, 0xb” przez `printf` z ROM, potem `assert(0)` w zadaniu warstwy łącza. Po restarcie hosta ślad podał:
zadanie `ble_ll_t`, „assert failed: st_tick br_c6_core.c:1007 (0)”, rodzaj „abort”, 24 adresy — po rozwiązaniu
`st_tick` ← `br_kick_handler` ← `npl_freertos_event_run` ← `r_ble_ll_task` ← `vPortTaskWrapper` — oraz ostatnie
96 znaków ROM kończące się całym wierszem asercji. Zwykły obraz 1.5.2, do którego strażnik wrócił po próbie,
odczytał ten sam zapis z NVS i podał go przez `--box`. Zapis próby ma własną wersję (`0x83`), więc końcowy
zwykły obraz nie pokazuje go jako awarii. W pierwszym obrazie próby było 12 adresów i funkcja z asercją wypadła
jako jedenasta — stąd 24.

**Czego to nie daje:** reset bez paniki (watchdog RTC, zanik zasilania) zostawia tylko powód resetu i miejsce
zadania warstwy łącza (`BR_AT_*`); jeśli host zresetuje C6 pinem, zanim C6 sam wstanie po awarii, zapis przepada.

### 2026-11-12 21:00 — przyczyna restartów: „zamiana bloku” w sterowniku; obrazy 1.5.3 i 1.5.4

Czarna skrzynka 1.5.2 złapała tego samego wieczoru dwie awarie zwykłego obrazu (głośnik włączony, właściciel
w domu):

1. **20:31, skan Classic — zawieszenie.** Zadanie warstwy łącza kręci się w przejściu po kolejce planisty
   (`r_ble_lll_sched_delete_by_sm_num_and_type`), wywołanym z `cancel_slot` ← `br_c6_cancel_all` ←
   `teardown_link_to_idle` ← polecenie hosta; po 10 s strażnik zadań (ślad `0xFC30/0x09`). Było to w fazie nazw
   po wyszukiwaniu: host wywołuje każde urządzenie audio bez znanej nazwy, czeka 1,8 s i wysyła
   `BR_VS_ABORT_ALL`.
2. **21:08, „połącz” z ekranu — asercja.** Ogon wydruku ROM: `BLE assert: line 912 in function
   r_ble_lll_mmgmt_block_copy, param: 0x0, 0x5`, stos: `r_ble_lll_recycle_sch_in_task` →
   `r_ble_lll_sched_pop_executed_sch` → `r_ble_lll_mmgmt_block_copy`, zanim poszedł pierwszy pakiet. Zapis
   z 2026-11-11 („osi_assert_wrapper”) to to samo miejsce, tylko bez tego wiersza.

**Mechanizm (z kodu sterownika, deasemblacja obrazu).** `r_ble_lll_sched_pop_executed_sch` zdejmuje z czoła
kolejki wykonane pozycje. Gdy rejestr stanu pasma (`0x600A1900`, młodsze 20 bitów) wciąż wskazuje zdejmowaną
pozycję — nic po niej nie zostało jeszcze oddane sprzętowi — sterownik nie może oddać tej pamięci, więc kopiuje
72 bajty do swojego zapasowego bloku (`r_ble_lll_mmgmt_block_copy`), zwraca kopię, a oryginał zatrzymuje jako
następny zapas. Kopiowanie sprawdza rodzaj bloku w słowie przed nim (3 najstarsze bity): bloki adaptera mają 5,
bloki sterownika 0; różne rodzaje przy celu ≤ 4 to asercja z wiersza 912 z parametrami (rodzaj celu, rodzaj
źródła) = (0, 5). Gdy zapasem jest akurat wcześniej zabrany blok adaptera, kopia przechodzi — i sterownik staje
się właścicielem pamięci, w której adapter buduje następną pozycję: stąd zepsuta kolejka i przejście bez końca
(także wcześniejsze resety strażnika przerwań „w przejściu po kolejce” z 2026-11-10).

**To nie rzadki przypadek.** Zakończona pozycja RX pozostaje pozycją pasma aż do startu następnego TX. Hak
w 1.5.3 naliczył 18 536 takich przebiegów w 2,5 minuty wywołań i skanów — ok. 120 na sekundę. Wszystkie
wcześniejsze obrazy przechodziły wtedy zamianę; kończyło się to awarią, gdy zapas nie był blokiem adaptera.
Kiedy nim nie jest — to wniosek, nie pomiar: po zamianie pozycji samego sterownika, co robią zdarzenia połączeń
LE (słuchawki w zasięgu i automat ponownego łączenia hosta). Pasuje do tego, że awarie były rano, wieczorem
i 2026-11-11 przy łączu LE, a nie po południu, gdy właściciel wyszedł ze słuchawkami.

**Poprawka (`c6_firmware/main/br_c6_radio.c`, obraz 1.5.3, `RESULT: PASS`):**

- hak `r_ble_lll_sched_pop_executed_sch` (`cmake/ble_hooks.txt`): wykonana pozycja Soft-BR, na którą pasmo
  jeszcze wskazuje, nie jest zdejmowana — przebieg dostaje „nic do zabrania”, a pozycję bierze następny, gdy
  pasmo przejdzie dalej. Licznik w śladzie `0xCD` (`--box`: wiersz GUARD);
- `br_c6_cancel_all` nie usuwa pozycji z kolejki sterownika: oznacza je jako porzucone i pozwala dobiec.

**Uzupełnienie 23:36 — obraz 1.5.4.** 1.5.3 (sam hak) został cofnięty po trzech nieudanych połączeniach;
później okazało się, że głośnik po każdym zerwaniu łącza przez kilka minut odmawia także na 1.5.2, więc
o 1.5.3 nic to nie mówi. 1.5.4 dodaje do haka „zaparkowanie": przytrzymana pozycja jest oznaczona, a adapter
zabiera taki slot RX od razu i bez `sched_delete` (które wypięłoby pozycję i oznaczyło odbiór jako pominięty).
Wyzwalacz potwierdzony tego wieczoru na 1.5.2: z włączonym automatem ponownego łączenia słuchawek LE
(`bt.autocon`) dwie próby połączenia po świeżym starcie skończyły się asercją z wiersza 912, z wyłączonym
głośnik połączył się od razu. Na 1.5.4 z włączonym `bt.autocon`, od 97 s po starcie: głośnik połączony bez
restartu, 4 minuty muzyki — 16 174 pakiety, 0 utraconych, bitpool 20 → 25, zajętość 82–84 %, poziom rozmiaru 0,
bez uderzeń — potem rozłączenie, dwa skany i cztery próby połączenia bez restartu. Nie sprawdzone na 1.5.4:
LE Audio na słuchawkach, skan z bezimiennymi urządzeniami audio w zasięgu, długa sesja. Rekord `0xCD` co 30 s
wypiera rekord startu ze śladu po kilku minutach pracy Classic (`--box` mówi wtedy „no start record”).

**Sprawdzone (1.5.3):** hak wpięty (verify_hooks: 1/1 odwołań), obraz wgrany 21:16 i potwierdzony przez strażnika,
kontrolna budowa daje ten sam obraz (ELF fd63be48); dziesięć poleceń Classic bez restartu. Opcja testowa
`BR_ST_ABORT_TEST=1` (co 2 s nowe wywołanie i przerwanie poprzedniego) przeszła 193 przerwania na adapterze
sprzed poprawki bez zawieszenia — z adresem, którego nikt nie ma — więc usterki nie odtwarza.
**Nie sprawdzone na 1.5.3:** nic z urządzeniem, które odpowiada (głośnik znów sam się wyłączył): połączenie,
strumień, słuchawki LE, oraz obie sytuacje, które padały. Nie ma też próby odtwarzającej usterkę na żądanie.

### Podsłuch odpowiedzi punktu dostępu Wi-Fi w tym samym obrazie (`CONFIG_CYBERDECK_WIFI_TAP`)

Niezależne od Soft-BR narzędzie diagnostyczne: `main/wifi_tap.c` zapisuje ramki zarządzające adresowane do stacji
(uwierzytelnienie z kodem stanu SAE, odpowiedź powiązania, deauth, disassoc) i oddaje je przez ten sam ślad (`0xC0`,
`0xC1`); `tools/br_selftest.py` je opisuje. Host dostaje od stosu Wi-Fi tylko kod przyczyny (2 = uwierzytelnienie
wygasło), a ramki pokazują, co punkt dostępu faktycznie odpowiedział. Wariant `sh c6_firmware/build.sh
--guard-test-wpa2` buduje ten sam obraz bez WPA3 (stacja łączy się z siecią WPA2/WPA3 przez WPA2).
