# Инвентаризация портов: что из 34 плагинов может работать в окне ручных инструментов

Таблица «порт × метод» показывает, какие методы портов можно запустить в окне ручных инструментов и почему остальные нельзя. Модель разрешений описана в [manual-plugins.md](manual-plugins.md), руководство пользователя в [docs/user/manual-plugins.md](../user/manual-plugins.md). Порт `onaidocs` появился позже и в инвентаризацию не входит.

Вердикты получены из четырёх источников. Самый надёжный (**W**) это секция импортов 34 собранных wasm-модулей. Затем чтение исходников пути каждого метода (**S**), существующие тесты портов (**T**) и граф вызовов по именам функций (**G**, слабый, используется только в строках «не подписывает»). Для объявленных операций вердикты затем подтверждены прогоном настоящего wasm через `plugin_call_approved` (`crates/oncl-core/tests/plugin_ports_manual/`, см. §6).

## 0. Итог в цифрах

- Портов (wasm-пакетов) 34, имён `modules` 35 (у `documentolog` два). Методов, видимых вызывающему через WSS, включая ветки диспетчера, 166.
- Пригодны (полностью или при условиях шаблона) 15 методов в 9 портах: `dogovor24`, `efactoring`, `energy`, `eproc`, `esf-osdkz`, `fhs`, `market`, `qiwi`, `rating1c`.
- Непригодны 59 методов. Ещё 92 метода не подписывают: они не применяют ключ, в окне не предлагаются и перечислены для полноты.
- Портов без единого пригодного метода 25 из 34 (§4.2).

## 1. Уровни доказательства

| Уровень | Что означает |
|---|---|
| **W** | Импорт `oncl::<имя>` есть в секции импортов wasm; бинарник разбирает скрипт `scripts/mp0_wasm_imports.py`. Показывает, что порт может вызвать функцию хоста, но не показывает, в каком методе. |
| **S** | Прочитан исходник пути метода: диспетчер, функция, вызываемые функции хоста. Номера строк указаны. |
| **T** | Поведение подтверждает существующий тест порта (`crates/oncl-port-tests/tests/*`). |
| **G** | Только имена в графе вызовов; приближение грубое и завышает набор вызовов. Используется лишь в строках «не подписывает». |

Модули собираются командой `cd plugins && cargo build --release --locked --target wasm32-unknown-unknown --workspace` (34 файла `oncl_port_*.wasm`). Это сборка без `--remap-path-prefix`, который добавляет `cargo xtask plugin pack`; на набор импортов это не влияет. Импорты читает `python scripts/mp0_wasm_imports.py <каталог>/wasm32-unknown-unknown/release`; результат совпадает с `Compiled::imports()` (модуль `oncl`, имена из `Import::name()` в `crates/oncl-pdk/src/abi.rs`). Все 34 модуля импортируют только из `oncl`, и все имена известны ABI.

## 2. Поведение хоста, от которого зависит вердикт

| # | Факт | Где | Следствие для ручного окна |
|---|---|---|---|
| F1 | `call_headless` создаёт новый экземпляр модуля на каждый вызов (`Guest::new(self, state)`), ничего не переживает вызов | `crates/oncl-plugin/src/headless.rs` | Состояние плагина в памяти wasm (`thread_local!`, `static Mutex`) между вызовами теряется. Через WSS экземпляр живёт всю сессию (`crates/oncl-plugin/src/modules.rs`), поэтому порты вида «`selectKey`, затем `sign`» работают через WSS и не работают вызов за вызовом. Это одна из главных причин непригодности (arta, buhta, devart, doodocs, skf, taxtech и другие). |
| F2 | `requires_interaction`: `Dialog*`, `KeysChoose/Select/FlowOpen/FlowPick`, `File*`, `CoreOpenWindow`, `Keystore*` дают `InteractionRequired` до диспетчеризации | `headless.rs` | На `select/choose` в ручном окне отвечает Core; `Dialog*` и `File*` остаются запрещены. |
| F3 | Бэкенд Core обслуживает только Hash, KeysSignRaw, Shared, Now, Log, Settings, PageFile, Http, KeysSign{Cms,CmsEx,Xml,XmlEx,Xades}, CmsVerify, Ca*/Ocsp/Crl/Tsp*, KeysDescribe/Chain/Release и общедоступные Random/CertInfo/CertDetails/XmlVerify/Platform/LocalTime. Остальное даёт `PermissionDenied`: `keys_open`, `keys_terminals`, `reply_drop`, `call_locale`, `core_*`, `tokens_*` | `crates/oncl-core/src/plugins/capabilities.rs` | `reply_drop` импортируют 33 из 34 портов, но вызывается он только на нечитаемый запрос, а запрос строит хост. В ручном окне `reply_drop` разрешён, `keys_terminals` отвечает `[]`. |
| F4 | `page_file_read` отдаёт только заранее привязанный вход с именем, равным точному пути; `page_file_write` принимает `dir`/`name` без `/ \ : NUL`, с расширением из `page_files_ext`, и только заранее привязанный выход | `capabilities.rs` | Порты, которым нужен диск страницы (`arta.signFilePath`, `ezsigner.signFilePath`), вызывают `page_file_write` с путём, содержащим букву диска. Запись отвергается уже после применения ключа, поэтому отказать заранее нельзя. |
| F5 | У ручного вызова нет Origin: `encode_input(request, caller.browser_origin(), "ru", None)`, `LocalOperator` даёт `None` | `headless.rs` | `request.origin` читают 7 портов из 34: buhta, k2sign, knp, nursign, qoltanba, taxtech, xdox. Только taxtech терпит `None` (подставляет `UNDEFINED`). `qoltanba` отвечает `INVALID_ORIGIN`, `xdox` отвечает `That module can be used only on https://xdox.kz`, buhta, k2sign, knp и nursign обрывают соединение. |
| F6 | Язык для плагина в headless-вызове всегда `"ru"` | `headless.rs` | Влияет только на тексты ответов; для пригодных методов не важен. |

Ворота `keys::terminals` стоят перед выбором ключа в ветке токенов общего `select` (`plugins/common/legacy/src/guest.rs`): пустой список даёт `STORAGE_EMPTY`. Поэтому шаблоны пригодных портов с `keys_terminals` (rating1c, eproc, esf-osdkz) подставляют `storageName=PKCS12`.

### 2.1 Классы импортов

| Класс | Импорты | Политика ручного окна |
|---|---|---|
| A | `keys_select`, `keys_choose`, `keys_release`, `keys_describe`, `keys_chain` | разрешены; на выбор отвечает Core для единственного привязанного ключа |
| T | `keys_terminals` | ответ `[]`; порт, которому для успеха нужен непустой список считывателей, непригоден (TERMINALS) |
| SIGN | `keys_sign_raw`, `keys_sign_cms`, `keys_sign_cms_ex`, `keys_sign_xml`, `keys_sign_xml_ex`, `keys_sign_xades` | одно применение ключа; профиль принуждает Core |
| F | `dialog_*`, `file_*`, `keys_open`, `page_file_*` | запрещены; если нужны на успешном пути, порт непригоден |
| NET | `ocsp_fetch`, `tsp_stamp`, `tsp_request`, `crl_fetch`, `ca_*`, `pkix_path` (PKI); `http_request_ex` (произвольный http(s)) | сеть показана в согласии; разрешены только серверы PKI |
| ST | `shared_*`, `settings_*` | состояние между вызовами в headless недоступно |
| V | `cms_verify`, `xml_verify` | локальная проверка |
| нейтральные | `log`, `now`, `random`, `cert_info`, `cert_details`, `hash`, `local_time`, `platform`, `reply_drop` | разрешены (см. F3 про `reply_drop`) |

### 2.2 Импорты портов (уровень **W**)

Колонки: выбор ключа (sel), терминалы (term), виды подписи (sign), диалоги (dlg), файлы и файлы страницы (file), `keys_open` (open), сеть (net), состояние (state), читает ли порт `request.origin` (origin, **yes** если читает). Последняя колонка: пригодных методов из подписывающих (по §3).
| Порт | modules | sel | term | sign | dlg | file | open | net | state | origin | supported / sign-методов |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `acbank` | `kz.acbank.business.api.ncalayer.module` | keys_select |  | raw | choice message |  |  |  | shared_get shared_put |  | 0 / 2 |
| `arta` | `kz.arta.synergy.signmodule` | keys_select | yes | cms_ex raw xml_ex |  | file_choose page_file_read page_file_write |  | ocsp_fetch |  |  | 0 / 4 |
| `bas` | `kz.bas.nca.multiSignService` | keys_select |  | cms_ex |  |  |  | ocsp_fetch tsp_stamp |  |  | 0 / 1 |
| `buhta` | `com.buhta.cert.ncamodule` | keys_select |  | cms_ex xml_ex |  |  |  |  |  | yes | 0 / 3 |
| `devart` | `kz.devart.bundle.Devart` | keys_select | yes | cms_ex raw xml |  |  |  | ocsp_fetch tsp_stamp |  |  | 0 / 1 |
| `documentolog` | `kz.documentolog.agent.SignService`, `kz.documentolog.agent.KalkanService` |  | yes | cms_ex xml_ex | choice password | file_choose | keys_open | http_request_ex |  |  | 0 / 4 |
| `dogovor24` | `kz.dogovor24.module` | keys_select |  | cms_ex |  |  |  | ocsp_fetch |  |  | 1 / 3 |
| `doodocs` | `kz.doodocs.moduleservice.SampleBundle` |  |  | cms_ex |  |  | keys_open |  |  |  | 0 / 2 |
| `efactoring` | `EFactoringSign` | keys_choose |  | cms_ex xml_ex | choice |  |  |  |  |  | 2 / 2 |
| `energy` | `kz.energy.sign.SignEnergy` | keys_select |  | cms_ex | message |  |  |  | settings_get settings_put |  | 1 / 1 |
| `eot` | `kz.gov.pki.eot.SignModule` | keys_select | yes | cms_ex |  |  |  | ca_issuer ocsp_fetch |  |  | 0 / 1 |
| `eproc` | `kz.sapa.eproc.osgi.EprocModule` | keys_select | yes | xml |  |  |  |  |  |  | 1 / 1 |
| `esf-osdkz` | `com.osdkz.esf.signer.esfSigner` | keys_select | yes | raw |  |  |  |  |  |  | 2 / 3 |
| `eup` | `kz.nitec.eup.eupsigner` | keys_select |  | cms_ex |  |  |  | ocsp_fetch |  |  | 0 / 1 |
| `ezsigner` | `kz.gov.pki.cms.CMSSignUtil` | keys_select | yes | cms_ex |  | file_choose page_file_read page_file_write |  | ca_issuer ocsp_fetch |  |  | 0 / 1 |
| `fhs` | `kz.fhs.cabinet.FHSCabinetSigner` | keys_select |  | cms_ex xml | choice | file_choose | keys_open | http_request_ex |  |  | 2 / 5 |
| `idocs` | `kz.idocs` | keys_select |  | cms_ex |  |  |  | ca_list ocsp_fetch |  |  | 0 / 1 |
| `k2sign` | `K2Sign` | keys_choose |  | cms_ex | message | file_open_ex |  | http_request_ex |  | yes | 0 / 2 |
| `knp` | `kz.inessoft.kgd.knp.ncalayer.KNPModuleService` |  | yes | xml_ex |  |  | keys_open | http_request_ex |  | yes | 0 / 1 |
| `market` | `MarketSign` | keys_choose |  | cms_ex xml_ex | choice |  |  |  |  |  | 2 / 2 |
| `metadoc` | `kz.metadoc.NCAModule` | keys_select | yes | cms_ex xml_ex | password | file_choose | keys_open | ca_issuer ocsp_fetch tsp_stamp |  |  | 0 / 2 |
| `motiw` | `ru.motiw.ModuleService` | keys_select | yes | cms_ex |  |  | keys_open |  |  |  | 0 / 1 |
| `nursign` | `NURSign` | keys_choose |  | cms_ex xml_ex | message | file_open_ex |  | http_request_ex |  | yes | 0 / 6 |
| `qiwi` | `kz.qiwi.osgi.SecurityUtils` | keys_select |  | xml_ex |  |  |  |  |  |  | 1 / 1 |
| `qoltanba` | `kz.btsdigital.qoltanba.CMSSignUtil` | keys_select | yes | cms_ex |  |  |  | ca_issuer ocsp_fetch |  | yes | 0 / 1 |
| `rating1c` | `kz.rating1c.edo.signUtils` | keys_select | yes | cms_ex raw xml_ex |  |  |  |  |  |  | 3 / 6 |
| `simourg` | `kz.Simourg.SimBASEModule` | keys_select | yes | cms_ex | choice |  |  | ca_list ocsp_fetch tsp_stamp |  |  | 0 / 2 |
| `skf` | `org.skf.osgi.SKFModule` |  | yes | xades | choice | file_choose | keys_open | http_request_ex ocsp_fetch |  |  | 0 / 1 |
| `taxtech` | `kz.digital.taxtech.documents.multisign.NCAModule` | keys_select |  | cms_ex raw xml |  |  |  |  |  | yes | 0 / 1 |
| `thundercrypt` | `asia.dbt.thundercrypt.osgi.ThunderCryptModule` |  |  | cms_ex | password |  | keys_open | ca_issuer crl_fetch ocsp_fetch tsp_request tsp_stamp |  |  | 0 / 1 |
| `uchet` | `kz.uchet.signUtil.commonUtils` | keys_select | yes | cms_ex xml_ex | message password | file_choose file_open_ex page_file_read page_file_write | keys_open | ca_issuer http_request_ex ocsp_fetch |  |  | 0 / 6 |
| `uchet-esf` | `kz.uchet.esfSignUtil` |  |  | raw xml |  |  | keys_open |  |  |  | 0 / 2 |
| `workspace` | `kz.workspace.Signer` | keys_select | yes | cms_ex | password |  | keys_open | ocsp_fetch tsp_stamp |  |  | 0 / 1 |
| `xdox` | `kz.xdox.signerbundle` | keys_select | yes | cms_ex |  |  |  | pkix_path |  | yes | 0 / 2 |

Число портов с импортом (из 34): `keys_release` 34, `log` 34, `random` 34, `reply_drop` 33, `keys_sign_cms_ex` 27, `keys_select` 24, `cert_info` 23, `cert_details` 22, `keys_terminals` 17, `now` 15, `ocsp_fetch` 15, `keys_open` 11, `keys_sign_xml_ex` 11, `local_time` 8, `dialog_choice` 7, `file_choose` 7, `http_request_ex` 7, `keys_sign_raw` 7, `ca_issuer` 6, `cms_verify` 6, `tsp_stamp` 6, `dialog_message` 5, `dialog_password` 5, `keys_sign_xml` 5, `keys_choose` 4, `platform` 4, `file_open_ex` 3, `hash` 3, `page_file_read` 3, `page_file_write` 3, `ca_list` 2, `keys_chain` 2, `xml_verify` 2, `crl_fetch` 1, `keys_sign_xades` 1, `pkix_path` 1, `settings_get` 1, `settings_put` 1, `shared_get` 1, `shared_put` 1, `tsp_request` 1.

## 3. Таблица «порт × метод»

Вердикты:

- **supported**: вызов работает как есть на привязанном ключе, без `Dialog*`, `File*` и `keys::open`, без Origin, без состояния между вызовами, с одной подписью, и подписывается аргумент запроса.
- **supported\***: то же при условиях из колонки «Причина / условия». Это значения параметров шаблона, которые задаёт хост; замена `cosign=Auto` на `Never`; диалог, достижимый только при ошибке, где трап `InteractionRequired` просто завершает вызов ошибкой.
- **unsupported**: есть причина из списка ниже.
- **no-sign**: метод не применяет ключ для подписи и в окне не предлагается.

Коды причин:

| Код | Значение |
|---|---|
| `ORIGIN` | нужен Origin страницы; у ручного вызова его нет, и он не подставляется |
| `DIALOG` | импорт `Dialog*` на успешном пути |
| `KEYS_OPEN` | `keys::open` с путём или байтами хранилища и паролем из запроса |
| `STATE` | нужно состояние экземпляра, оставленное предыдущим вызовом той же сессии; ручной вызов всегда получает новый экземпляр |
| `OPTIONS` | опции подписи вне допустимого профиля (`attrs.extra` ЭСЭДО, `econtent_type`, своя TSA) |
| `MULTI` | больше одной подписи за вызов (`max_uses = 1`) |
| `FILE` | нужны `File*` или `page_file_*` |
| `DERIVED` | подписываются байты, которые плагин вычисляет или скачивает сам, а не аргумент |
| `COSIGN` | `cosign = Into(cms)`: соподпись CMS из запроса |
| `HTTP` | успешному пути нужен произвольный http(s)-сервер вне PKI (лицензионный сервер поставщика) |
| `TERMINALS` | успех зависит от `keys::terminals`, а в окне список пуст |

Колонки: «Импорты метода» это функции хоста на пути метода по исходнику; «Вид / опции» это вид применения ключа и опции, которые выбирает плагин; «Подписей» это число применений ключа за вызов; «State» это состояние между вызовами; «Содержимое» это bound (аргумент) или derived (вычислено или получено плагином); «Док-во» это уровень и ссылки `файл:строка` относительно `plugins/` или `crates/`. Ячейки таблицы оставлены на английском, как в исходных заметках к коду.

| Порт | Метод | Вердикт | Причина / условия | Импорты метода | Вид / опции | Подписей | Origin | State | Содержимое | Док-во |
|---|---|---|---|---|---|---|---|---|---|---|
| `acbank` | `healthcheck` | **no-sign** |  | shared_get | - | 0 | no | reads shared window mark | - | S: acbank/src/lib.rs:122 |
| `acbank` | `signJsonWithJws` | **unsupported** | `DIALOG`, `MULTI`, `DERIVED` | dialog_choice (window loop), keys_select, keys_sign_raw xN, shared_put/get | raw; one raw signature per item over the plugin-built JWS signing input (header.payload) | N=len(signableItems) | no | shared_put/get window mark (re-entry guard) | derived (JWS input built from item JSON) | W+S: acbank/src/lib.rs:281, acbank/src/lib.rs:238 |
| `acbank` | `multiSignJsonWithJws` | **unsupported** | `DIALOG`, `MULTI`, `DERIVED` | dialog_choice (window loop), keys_select, keys_sign_raw xN, shared_put/get | raw; one raw signature per item over the plugin-built JWS signing input (header.payload) | N=len(signableItems) | no | shared_put/get window mark (re-entry guard) | derived (JWS input built from item JSON) | W+S: acbank/src/lib.rs:281, acbank/src/lib.rs:238 |
| `arta` | `getActiveTokens` | **no-sign** |  | keys_terminals | - | 0 | no | no | - | W+S: arta/src/port.rs:179 |
| `arta` | `checkModuleAvailability` | **no-sign** |  | - | - | 0 | no | no | - | S: arta/src/port.rs:189 |
| `arta` | `getKeyInfo` | **no-sign** |  | keys_select(Action::KeyInfo), keys_terminals | - | 0 | no | WRITES STATE (selected key kept in thread_local STATE) | - | W+S: arta/src/port.rs:260, arta/src/port.rs:99 |
| `arta` | `getFullKeyInfo` | **no-sign** |  | keys_select(KeyInfo) | - | 0 | no | writes state | - | W+S: arta/src/port.rs:278 |
| `arta` | `signFilePath` | **unsupported** | `STATE`, `FILE`, `DERIVED`; after the key use the output dir (contains ':' and separators) is rejected by write_bound_file | page_file_read, page_file_write, keys_sign_cms_ex | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | READS STATE (STATE.selected from getKeyInfo) | derived (file read by page path) | W+S+T: arta/src/port.rs:317, arta/src/port.rs:297, oncl-core/src/capabilities.rs:243 |
| `arta` | `signBase64File` | **unsupported** | `STATE`; without state the plugin swallows the error and answers code 200 with an empty responseObject (sign_base64_file) — a fake success | keys_sign_cms_ex | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | READS STATE | bound (base64 arg 0) | W+S+T: arta/src/port.rs:354, oncl-port-tests/tests/clones.rs:2038 |
| `arta` | `signDocument` | **unsupported** | `STATE` | keys_sign_raw, (digest object with fileNames: ocsp_fetch + keys_sign_cms_ex) | raw (+cms_ex ESEDO); INFO: no signing; SIGN: raw over dataForSign; with digest.fileNames also an ESEDO CMS with Custom TSA | >=1 (2 with fileNames) | no | READS STATE | bound (dataForSign) + derived (ESEDO) | W+S: arta/src/port.rs:372 |
| `arta` | `showFileChooser` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: arta/src/port.rs:512 |
| `arta` | `signXML` | **unsupported** | `STATE` | keys_sign_xml_ex | xml_ex; placement=FirstChildOfDocument, c14n Inclusive, transforms Enveloped+C14N-with-comments, sig/digest URIs by cert (rsa_sha256\|gost2004; GOST2015 -> default), strip_whitespace, declaration+standalone=no | 1 | no | READS STATE; null on failure | bound (xml arg 0) | W+S: arta/src/port.rs:552, arta/src/port.rs:561 |
| `bas` | `sign (single op, args=[b64,fileNames])` | **unsupported** | `OPTIONS` | keys_select, ocsp_fetch, keys_sign_cms_ex, tsp_stamp | cms_ex + tsp_stamp; econtent_type=1.3.6.1.4.1.6801.11.1.9, attrs.extra = 5 ESEDO attrs incl. OCSP response, signingTime UTCTime, ts=TsaChoice::Custom (tsp_stamp Replace/Append) | 1 | no | no | bound data (arg 0) but attrs carry network-derived bytes | W+S: bas/src/lib.rs:44, bas/src/lib.rs:108 |
| `buhta` | `call#1 SELECT_SIGN_CERT` | **unsupported** | `ORIGIN`, `STATE` | keys_select | - | 0 | YES (presence, any value): drops the connection | WRITES STATE (SELECTED uuid -> key) | - | W+S+T: buhta/src/lib.rs:118, buhta/src/lib.rs:41, oncl-port-tests/tests/heavy.rs:89 |
| `buhta` | `call#2 SIGN_DOCUMENT` | **unsupported** | `ORIGIN` | keys_select, keys_sign_cms_ex \| keys_sign_xml_ex | cms_ex (file) / xml_ex (xml); file: encapsulate=attached(param), cosign=Auto, ts=Kalkan, std attrs; xml: placement DocumentElement, URIs by key alg, enveloped | 1 | YES (presence) | may read SELECTED (sign.cert uuid) or select by tin | bound (document in payload protobuf/JSON) | W+S+T: buhta/src/lib.rs:118, buhta/src/lib.rs:289, buhta/src/lib.rs:331 |
| `buhta` | `call#3 BULK_SIGN_DOCUMENT` | **unsupported** | `ORIGIN`, `MULTI` | as handler 2 | cms_ex / xml_ex; as handler 2 | N=documents.len() | YES (presence) | as handler 2 | bound | W+S+T: buhta/src/lib.rs:118, buhta/src/lib.rs:298 |
| `devart` | `getSignerInfo` | **no-sign** | `STATE` | keys_select, keys_terminals | - | 0 | no | WRITES STATE (static SIGNERS token -> key) | - | W+S: devart/src/lib.rs:309, devart/src/lib.rs:85 |
| `devart` | `signDevart` | **unsupported** | `STATE`, `MULTI`, `OPTIONS` | keys_sign_raw (ESF), keys_sign_xml (XML), keys_sign_cms_ex + tsp_stamp (CMS), ocsp_fetch | raw / xml / cms_ex; CMS: cosign Never or Into(existing CMS), attrs without scv2, ts via tsp_stamp Custom TSA per signer; ESF raw; XML default | N=len(dataList) | no | READS STATE (token from getSignerInfo) | bound per item | W+S: devart/src/lib.rs:525, devart/src/lib.rs:657, devart/src/lib.rs:724 |
| `devart` | `extractFromCms` | **no-sign** |  | - | - | 0 | no | no | - | S: devart/src/lib.rs:768 |
| `documentolog` | `SignService.browseKeyStore` | **no-sign** | `DIALOG`, `FILE` | dialog_password, dialog_choice, file_choose, keys_terminals | - | 0 | no | writes STATE (kept password) | - | W+S: documentolog/src/lib.rs:209 |
| `documentolog` | `KalkanService.browseKeyStore` | **no-sign** | `DIALOG`, `FILE` | dialog_password, dialog_choice, file_choose, keys_terminals | - | 0 | no | writes STATE (kept password) | - | W+S: documentolog/src/lib.rs:209 |
| `documentolog` | `SignService.getKeys` | **no-sign** | `DIALOG`, `KEYS_OPEN` | dialog_password, keys_open | - | 0 | no | writes STATE (password) | - | W+S: documentolog/src/lib.rs:314 |
| `documentolog` | `KalkanService.getKeys` | **no-sign** | `DIALOG`, `KEYS_OPEN` | dialog_password, keys_open | - | 0 | no | writes STATE (password) | - | W+S: documentolog/src/lib.rs:314 |
| `documentolog` | `SignService.getSPAndSign / sign` | **unsupported** | `DIALOG`, `KEYS_OPEN`, `DERIVED`, `OPTIONS` | http_request_ex (challenge + order + document), dialog_password, keys_open, keys_sign_cms_ex / keys_sign_xml_ex | cms_ex (ESEDO / simple / CAdES) / xml_ex; ESEDO attrs.extra; Digest content (server digest); XML FirstChild enveloped | 1 | no (http origin only) | STATE (password) | derived (digest or document URL from the server's order) | W+S: documentolog/src/lib.rs:547, documentolog/src/lib.rs:440 |
| `documentolog` | `SignService.getSSAndSign` | **unsupported** | `DIALOG`, `KEYS_OPEN`, `DERIVED`, `OPTIONS` | http_request_ex (challenge + order + document), dialog_password, keys_open, keys_sign_cms_ex / keys_sign_xml_ex | cms_ex (ESEDO / simple / CAdES) / xml_ex; ESEDO attrs.extra; Digest content (server digest); XML FirstChild enveloped | 1 | no (http origin only) | STATE (password) | derived (digest or document URL from the server's order) | W+S: documentolog/src/lib.rs:547, documentolog/src/lib.rs:440 |
| `documentolog` | `KalkanService.createCMSEsedoSignature` | **unsupported** | `DIALOG`, `KEYS_OPEN`, `DERIVED`, `OPTIONS` | http_request_ex (sign_string_url), dialog_password, keys_open, keys_sign_cms_ex | cms_ex; ESEDO attrs.extra (file names, OCSP from page), attached=param | 1 | no | STATE (password) | derived (document downloaded from page URL) | W+S: documentolog/src/lib.rs:504 |
| `documentolog` | `KalkanService.createCMSSimpleSignature` | **unsupported** | `DIALOG`, `KEYS_OPEN`, `DERIVED` | http_request_ex, dialog_password, keys_open, keys_sign_cms_ex | cms_ex; encapsulate=param, cosign Never, certs=Chain, signs the BASE64 TEXT of the downloaded data | 1 | no | STATE (password) | derived (downloaded, then base64-encoded) | W+S: documentolog/src/lib.rs:504, documentolog/src/lib.rs:472 |
| `documentolog` | `KalkanService.init` | **no-sign** |  | - | - | 0 | no | no | - | S: documentolog/src/lib.rs:147 |
| `documentolog` | `KalkanService.getCertInfo` | **no-sign** | `KEYS_OPEN` | keys_open, dialog_password | - | 0 | no | STATE (password) | - | S: documentolog/src/lib.rs:147 |
| `documentolog` | `KalkanService.getSubjectDN` | **no-sign** | `KEYS_OPEN` | keys_open, dialog_password | - | 0 | no | STATE (password) | - | S: documentolog/src/lib.rs:147 |
| `documentolog` | `KalkanService.getCurrentUser` | **no-sign** |  | - | - | 0 | no | no | - | S: documentolog/src/lib.rs:147 |
| `documentolog` | `KalkanService.getCurrentStoragePath` | **no-sign** |  | - | - | 0 | no | no | - | S: documentolog/src/lib.rs:147 |
| `dogovor24` | `signCMS (args=[b64])` | **supported*** | key is selected before the method name is read; requires cert EKU present and without clientAuth (plugin check) | keys_select, keys_sign_cms_ex (+ Kalkan TSA inside the sign call), cert_info, random | cms_ex; encapsulate=true, cosign=Auto (coerce to Never), ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64 arg 0) | W+S+T: dogovor24/src/lib.rs:161, dogovor24/src/lib.rs:83, oncl-port-tests/tests/medium.rs:1984 |
| `dogovor24` | `batchSignCMS (args=[b64...])` | **unsupported** | `MULTI` | as signCMS | cms_ex; as signCMS, one signature per element | N=args.len() (1 element == signCMS) | no | no | bound | W+S: dogovor24/src/lib.rs:137 |
| `dogovor24` | `signEsedo (args=[b64,fileNames])` | **unsupported** | `OPTIONS` | ocsp_fetch, keys_sign_cms_ex | cms_ex; ESEDO attrs.extra (file names, ESEDO marker, signer DN, OCSP response), detached, Generalized signingTime, no TSA | 1 | no | no | bound data; attrs carry network data | W+S+T: dogovor24/src/lib.rs:49, dogovor24/src/lib.rs:205 |
| `doodocs` | `auth` | **unsupported** | `KEYS_OPEN`, `STATE` | keys_open (KeySource::Bytes + password text), cert_info, now | - | 0 | no | WRITES STATE (static SESSION signer, 5 min) | - | W+S: doodocs/src/lib.rs:129, doodocs/src/lib.rs:41 |
| `doodocs` | `createCAdESFromBase64` | **unsupported** | `STATE`, `KEYS_OPEN` | keys_sign_cms_ex | cms_ex; encapsulate=attached(param), cosign=Auto, ts=Kalkan, std attrs | 1 | no | READS STATE (SESSION from auth) | bound | W+S: doodocs/src/lib.rs:181, doodocs/src/lib.rs:247 |
| `doodocs` | `logOut` | **no-sign** |  | now | - | 0 | no | state only | - | S: doodocs/src/lib.rs:167 |
| `doodocs` | `isAuthorized` | **no-sign** |  | now | - | 0 | no | state only | - | S: doodocs/src/lib.rs:167 |
| `efactoring` | `version` | **no-sign** |  | - | - | 0 | no | no | - | S: efactoring/src/lib.rs:47 |
| `efactoring` | `text {data, attach?, has_timestamp?}` | **supported*** | the retry dialog (dialog_choice) traps with InteractionRequired: a failed signing ends the call as a host error instead of the plugin's retry window | keys_choose, keys_sign_cms_ex; dialog_choice only on failure | cms_ex; encapsulate=param attach (template: false), cosign=Auto (coerce Never), ts=Kalkan iff has_timestamp (template: true), attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (text param, UTF-8 bytes) | W+S+T: efactoring/src/lib.rs:64, efactoring/src/lib.rs:221, efactoring/src/lib.rs:250, oncl-port-tests/tests/ecc.rs:118 |
| `efactoring` | `xml {data, sign_element?, signature_parent_element?}` | **supported*** | XPaths are page text: in the window they must be typed params shown in the consent | keys_choose, keys_sign_xml_ex; dialog_choice only on failure | xml_ex; no element: placement DocumentElement; with element: placement Parent + element/parent XPaths (params), SOAP-ENV ns, c14n Exclusive, transforms Enveloped+C14N-with-comments; strip_whitespace, no line breaks, no declaration | 1 | no | no | bound (data, source must be 'local') | W+S+T: efactoring/src/lib.rs:86, efactoring/src/lib.rs:146 |
| `efactoring` | `binary` | **no-sign** | never signs: after the key dialog answers CANCEL or the failed-download window | keys_choose; dialog_choice | - | 0 | no | no | - | S: efactoring/src/lib.rs:122 |
| `energy` | `ping` | **no-sign** |  | - | - | 0 | no | no | - | S: energy/src/lib.rs:44 |
| `energy` | `getKeyInfo` | **no-sign** |  | keys_select(KeyInfo), settings_get/put | - | 0 | no | WRITES SETTINGS (alias record) | - | W+S: energy/src/lib.rs:97, energy/src/lib.rs:145 |
| `energy` | `sign {data:[{id,name,base64}], encapsulate?, isDigested?, tsaProfile?, alias?}` | **supported*** | dialog_message is reached only on failure (ALIAS_MISMATCH/SIGNING_ERROR/UNKNOWN_ERROR) -> trap | keys_select, keys_sign_cms_ex; dialog_message on error paths only | cms_ex; encapsulate=param (default true), cosign=Auto (Never if isDigested), content Data (Digest iff isDigested -> template false), ts=Kalkan iff tsaProfile, certs=Default(Signer), attrs ct+md+scv2+signingTime | N=len(data) (template: 1) | no | alias given -> REMEMBERED (static) and alias-mismatch dialog (template: omit alias) | bound (base64 of data[0]) | W+S+T: energy/src/lib.rs:162, energy/src/lib.rs:236, energy/src/lib.rs:26, oncl-port-tests/tests/medium.rs:538 |
| `eot` | `signCmsWithSignedAttrs(storage,keyType,b64,flag,fileNames)` | **unsupported** | `OPTIONS` | keys_select, keys_terminals(token only), ca_issuer, ocsp_fetch, keys_sign_cms_ex | cms_ex; content=Digest(arg: the page's digest), ESEDO attrs.extra incl. OCSP BasicResponse, detached, ts=Kalkan | 1 | no | no | Digest of an argument (page computed) | W+S: eot/src/lib.rs:37, eot/src/lib.rs:123 |
| `eproc` | `version` | **no-sign** |  | - | - | 0 | no | no | - | S: eproc/src/lib.rs:92 |
| `eproc` | `signXml {uid,chain?,storageName,keyType,xml,tbsElementXPath?,signatureParentElementXPath?}` | **supported*** | template: storageName=PKCS12 (no terminals call), keyType=SIGNATURE (bound key must have KNCA type SIGNATURE) | keys_select (+keys_terminals for token storages), keys_sign_xml, random | xml (keys_sign_xml, Core defaults); whole document, or element tbs with signature in parent (typed XPath params); no options chosen by the plugin | 1 | no | chain token = static CHAIN, only an optimisation (template: chain empty) | bound (xml param) | W+S: eproc/src/lib.rs:128, eproc/src/lib.rs:210, eproc/src/lib.rs:166 |
| `esf-osdkz` | `signPlainData {storageName,data}` | **supported*** | signs arbitrary text with a raw signature: the consent must show the text (design: raw only bound) | keys_select, keys_sign_raw, cert_details, cert_info | raw; raw signature of data's UTF-8 bytes, Action::Sign, filter KNCA=SIGNATURE; refuses algs other than gost2004/gost2015_512/rsa_sha256 | 1 | no | no | bound (data string) | W+S: esf-osdkz/src/lib.rs:112, esf-osdkz/src/lib.rs:227 |
| `esf-osdkz` | `auth {storageName,data}` | **supported*** | Action::Authenticate (a login challenge): the design has no ruling for Authenticate-kind use in the manual window | keys_select, keys_sign_raw | raw; raw signature of data; Action::Authenticate; AUTHENTICATION key, else SIGNATURE+GOST2015 fallback | 1 | no | no | bound (data string) | W+S: esf-osdkz/src/lib.rs:163 |
| `esf-osdkz` | `signPlainDataMap {storageName,data:{k:v..}}` | **unsupported** | `MULTI` | keys_select, keys_sign_raw xN | raw; one raw signature per map value | N=len(data) | no | no | bound | W+S: esf-osdkz/src/lib.rs:125 |
| `eup` | `sign (single op, args=[b64,fileNames])` | **unsupported** | `OPTIONS` | keys_select, ocsp_fetch, keys_sign_cms_ex | cms_ex; ESEDO attrs.extra incl. OCSP response, detached, Generalized time, no TSA | 1 | no | no | bound data; attrs carry network data | W+S: eup/src/lib.rs:46, eup/src/lib.rs:130 |
| `ezsigner` | `changeLang` | **no-sign** |  | - | - | 0 | no | LANG thread_local | - | S: ezsigner/src/port.rs:112 |
| `ezsigner` | `getMessage` | **no-sign** |  | - | - | 0 | no | no | - | S: ezsigner/src/port.rs:118 |
| `ezsigner` | `getDirectoryPath` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: ezsigner/src/port.rs:132 |
| `ezsigner` | `getFilePath` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: ezsigner/src/port.rs:148 |
| `ezsigner` | `signFilePath(filePath,fileDir,storageName)` | **unsupported** | `FILE`, `DERIVED`; the key is applied before page_file_write, whose dir (a drive path with ':' and separators) is rejected by write_bound_file: after-key failure | platform, page_file_read, keys_select, keys_terminals, ocsp_fetch, ca_issuer, keys_sign_cms_ex, page_file_write | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | LANG only | derived (file read by page path, Windows drive paths only) | W+S: ezsigner/src/port.rs:189, ezsigner/src/port.rs:171, oncl-core/src/capabilities.rs:243 |
| `fhs` | `getTradeCabBundleVersion` | **no-sign** |  | - | - | 0 | no | no | - | S: fhs/src/lib.rs:145 |
| `fhs` | `getCertificatePath` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: fhs/src/lib.rs:158 |
| `fhs` | `getCertificateInfo` | **no-sign** | `KEYS_OPEN` | keys_open (path+password) | - | 0 | no | no | - | W+S: fhs/src/lib.rs:193, fhs/src/lib.rs:180 |
| `fhs` | `signTextV2 {base64data,path,password}` | **unsupported** | `KEYS_OPEN` | keys_open, keys_sign_cms_ex | cms_ex; encapsulate=false, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64data) | W+S: fhs/src/lib.rs:363, fhs/src/lib.rs:180 |
| `fhs` | `signXmlV2 {xml,path,password}` | **unsupported** | `KEYS_OPEN` | keys_open, keys_sign_xml | xml; Core defaults | 1 | no | no | bound (xml) | W+S: fhs/src/lib.rs:397 |
| `fhs` | `signXml {xml} (V1)` | **supported*** | dialog_choice only on failure -> trap | keys_select (storages V1_STORAGES), keys_sign_xml; dialog_choice on failure only | xml; Core defaults, whole document | 1 | no | no | bound (xml) | W+S: fhs/src/lib.rs:463, fhs/src/lib.rs:444, fhs/src/lib.rs:427 |
| `fhs` | `signText {base64data} (V1)` | **supported*** | dialog_choice only on failure -> trap | keys_select, keys_sign_cms_ex; dialog_choice on failure only | cms_ex; encapsulate=false, cosign=Auto (coerce Never), ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64data) | W+S: fhs/src/lib.rs:505, fhs/src/lib.rs:312 |
| `fhs` | `signFile {url} (V1)` | **unsupported** | `DERIVED` | http_request_ex (GET url), keys_select, keys_sign_cms_ex | cms_ex; encapsulate=false, cosign=Auto, ts=Kalkan | 1 | no (http origin allow-list only) | no | derived (document downloaded from the page's URL) | W+S: fhs/src/lib.rs:477 |
| `idocs` | `sign {name,data}` | **unsupported** | `OPTIONS` | keys_select, ca_list, ocsp_fetch, keys_sign_cms_ex | cms_ex; ESEDO attrs.extra (name as file name, OCSP response of NCA GOST 2022 issuer), GOST2015-512 digest profile | 1 | no | no | bound data; attrs carry network data | W+S: idocs/src/lib.rs:57, idocs/src/lib.rs:182 |
| `k2sign` | `version` | **no-sign** | `ORIGIN`; the origin is read before `type`: even `version` drops without it | http_request_ex, cms_verify, dialog_message | - | 0 | YES (presence; also used as base URL) | no | - | W+S+T: k2sign/src/lib.rs:70, k2sign/src/lib.rs:1, oncl-port-tests/tests/ecc.rs:1309 |
| `k2sign` | `login` | **unsupported** | `ORIGIN`, `DERIVED`; the origin is read before `type`: even `version` drops without it | keys_choose, keys_sign_cms_ex, http_request_ex (upload) | cms_ex; encapsulate=false, cosign=Auto, ts=Kalkan iff has_tsa, std attrs | 1 | YES (presence; also used as base URL) | no | login: sessionId text; file: downloaded or user-picked file | W+S+T: k2sign/src/lib.rs:70, k2sign/src/lib.rs:106, oncl-port-tests/tests/ecc.rs:1309 |
| `k2sign` | `file` | **unsupported** | `ORIGIN`, `DERIVED`, `FILE`; the origin is read before `type`: even `version` drops without it | keys_choose, keys_sign_cms_ex, http_request_ex (upload) | cms_ex; encapsulate=false, cosign=Auto, ts=Kalkan iff has_tsa, std attrs | 1 | YES (presence; also used as base URL) | no | login: sessionId text; file: downloaded or user-picked file | W+S+T: k2sign/src/lib.rs:70, k2sign/src/lib.rs:132, oncl-port-tests/tests/ecc.rs:1309 |
| `k2sign` | `verify` | **no-sign** | `ORIGIN`; the origin is read before `type`: even `version` drops without it | http_request_ex, cms_verify, dialog_message | - | 0 | YES (presence; also used as base URL) | no | - | W+S+T: k2sign/src/lib.rs:70, k2sign/src/lib.rs:217, oncl-port-tests/tests/ecc.rs:1309 |
| `k2sign` | `verifyAll` | **no-sign** | `ORIGIN`; the origin is read before `type`: even `version` drops without it | http_request_ex, cms_verify, dialog_message | - | 0 | YES (presence; also used as base URL) | no | - | W+S+T: k2sign/src/lib.rs:70, k2sign/src/lib.rs:231, oncl-port-tests/tests/ecc.rs:1309 |
| `knp` | `info` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:41 |
| `knp` | `getAuthAccounts` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:42 |
| `knp` | `getStorageType` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:43 |
| `knp` | `getStorageDevicesByType` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:44 |
| `knp` | `hardwarePair` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:45 |
| `knp` | `attachDeviceToAccount` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:46 |
| `knp` | `getCertificates` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:47 |
| `knp` | `accountStatus` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:49 |
| `knp` | `getAgreementText` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:50 |
| `knp` | `signAgreement` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:51 |
| `knp` | `cancelAgreement` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:52 |
| `knp` | `changeAgreement` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:53 |
| `knp` | `signUp` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:54 |
| `knp` | `confirmSignUp` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:55 |
| `knp` | `resetPassword` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:56 |
| `knp` | `confirmResetPassword` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:57 |
| `knp` | `changeConfirmationType` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:58 |
| `knp` | `confirmChangeConfirmationType` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:60 |
| `knp` | `changePassword` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:63 |
| `knp` | `confirmChangePassword` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:64 |
| `knp` | `signDocument {storageType/path/password,xml,outputFormat}` | **unsupported** | `ORIGIN`, `KEYS_OPEN` | keys_open (keys.rs), keys_terminals, keys_sign_xml_ex | xml_ex; by keys.rs::sign_xml | 1 | YES (presence) | no | bound (xml) | W+S: knp/src/lib.rs:80, knp/src/lib.rs:262, knp/src/keys.rs:51 |
| `market` | `version` | **no-sign** |  | - | - | 0 | no | no | - | S: market/src/lib.rs:41 |
| `market` | `text {data, attach?, has_timestamp?}` | **supported*** | dialog_choice on failure -> trap | keys_choose, keys_sign_cms_ex; dialog_choice on failure only | cms_ex; encapsulate=param attach (template false), cosign=Auto (coerce Never), ts=Kalkan iff has_timestamp, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (text param) | W+S+T: market/src/lib.rs:59, market/src/lib.rs:150, oncl-port-tests/tests/ecc.rs:118 |
| `market` | `xml {data}` | **supported*** | dialog_choice on failure -> trap | keys_choose, keys_sign_xml_ex; dialog_choice on failure only | xml_ex; whole document, default placement, strip_whitespace, no line breaks, no declaration | 1 | no | no | bound (xml) | W+S+T: market/src/lib.rs:82, market/src/lib.rs:105 |
| `metadoc` | `getKeyInfo(storage)` | **no-sign** |  | keys_select(KeyInfo), keys_terminals | - | 0 | no | no | - | W+S: metadoc/src/port.rs:223 |
| `metadoc` | `getModuleVersion` | **no-sign** |  | - | - | 0 | no | no | - | S: metadoc/src/port.rs:179 |
| `metadoc` | `getKeyInfoByFilePathAndPassword` | **no-sign** | `KEYS_OPEN` | keys_open | - | 0 | no | no | - | W+S: metadoc/src/port.rs:268 |
| `metadoc` | `getFilePath` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: metadoc/src/port.rs:249 |
| `metadoc` | `signXml {keyType,filePath\|tokenName,password?,xml}` | **unsupported** | `KEYS_OPEN` | keys_open; dialog_password iff password blank; keys_sign_xml_ex | xml_ex; whole document (sign_xml(.., '', '')) | 1 | no | no | bound (xml) | W+S: metadoc/src/port.rs:363, metadoc/src/port.rs:289 |
| `metadoc` | `(any other method name) sign {dataForSign,filesNames,hashed?,...}` | **unsupported** | `KEYS_OPEN`, `OPTIONS`, `DIALOG` | keys_open, dialog_password iff password blank, ca_issuer, ocsp_fetch, keys_sign_cms_ex, tsp_stamp, cms_verify | cms_ex + tsp; ESEDO attrs.extra, hashed -> Digest, Custom TSA, post-sign self check | 1 | no | no | bound/Digest of arg, attrs network-derived | W+S: metadoc/src/port.rs:403, metadoc/src/port.rs:442 |
| `motiw` | `getStoragesList` | **no-sign** |  | keys_terminals | - | 0 | no | no | - | W+S: motiw/src/lib.rs:254 |
| `motiw` | `getContainerList` | **no-sign** |  | keys_terminals | - | 0 | no | no | - | W+S: motiw/src/lib.rs:269 |
| `motiw` | `getCertificateList` | **no-sign** | `KEYS_OPEN` | keys_open | - | 0 | no | no | - | G: motiw/src/lib.rs:326 |
| `motiw` | `verify` | **no-sign** |  | cms_verify | - | 0 | no | no | - | W+S: motiw/src/lib.rs:414 |
| `motiw` | `showStorageKey` | **no-sign** |  | keys_select(KeyInfo) | - | 0 | no | no | - | W+S: motiw/src/lib.rs:164 |
| `motiw` | `sign(storage,container,password,alias,data,format,attach)` | **unsupported** | `KEYS_OPEN` | keys_open (token reader + password), keys_sign_cms_ex | cms_ex; encapsulate=attach(arg), cosign=Auto, ts=Kalkan iff format>1, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64 arg 4) | W+S: motiw/src/lib.rs:340 |
| `nursign` | `version` | **no-sign** | `ORIGIN`; every error path also calls dialog_message | - | - | 0 | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `text` | **unsupported** | `ORIGIN`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | cms_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | 1 | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:112, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `multitext` | **unsupported** | `ORIGIN`, `MULTI`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | cms_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | N | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:124, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `binary` | **unsupported** | `ORIGIN`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | cms_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | 1 | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:148, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `xml` | **unsupported** | `ORIGIN`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | xml_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | 1 | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:183, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `multixml` | **unsupported** | `ORIGIN`, `MULTI`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | xml_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | N | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:200, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `file` | **unsupported** | `ORIGIN`, `FILE`, `DERIVED`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | cms_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | 1 | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:221, oncl-port-tests/tests/ecc.rs:648 |
| `qiwi` | `signXml [callID, xml]` | **supported*** (declared as two operations, one per key algorithm; see §6) | algorithm URIs depend on the key: the profile must accept Kalkan's URIs of the key (default) — for GOST 2015 keys the plugin asks GOST 2004 URIs, which the core's `known URIs fitting the key` rule may refuse (abi.rs SignXmlExArgs.signature_method) | keys_select, keys_sign_xml_ex, xml_verify, now | xml_ex; placement=FirstChildOfDocument, c14n Inclusive, transforms Enveloped+C14N-with-comments, signature/digest URIs by cert signature alg (RSA-SHA1, RSA-SHA256, else GOST 2004 URIs, GOST 2015 included), strip_whitespace=false, declaration+standalone=no | 1 | no | SESSION (static) is only a 20-minute key cache; first call selects | bound (xml arg 1) | W+S+T: qiwi/src/lib.rs:104, qiwi/src/lib.rs:145, oncl-port-tests/tests/medium.rs:1342 |
| `qiwi` | `logOut` | **no-sign** |  | - | - | 0 | no | clears SESSION | - | S: qiwi/src/lib.rs:84 |
| `qoltanba` | `signFileBytes(data,storage)` | **unsupported** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | keys_select, keys_terminals, ca_issuer, ocsp_fetch, keys_sign_cms_ex, cms_verify | cms_ex; encapsulate=true?, cosign=Auto, ts=Kalkan, std attrs | 1 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | bound (base64 arg 0) | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `checkCMSBytes` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `visualCMS` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `extractSignedFileBytes` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `changeLang` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `getMessage` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `getJson` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `rating1c` | `getActiveTokens` | **no-sign** |  | keys_terminals | - | 0 | no | no | - | W+S: rating1c/src/port.rs:83 |
| `rating1c` | `getKeyInfo` | **no-sign** |  | keys_select(KeyInfo) | - | 0 | no | no | - | W+S: rating1c/src/port.rs:186 |
| `rating1c` | `TestConnect` | **no-sign** |  | - | - | 0 | no | no | - | S: rating1c/src/port.rs:93 |
| `rating1c` | `TestKeyOwner` | **no-sign** |  | keys_select(KeyInfo) | - | 0 | no | no | - | W+S: rating1c/src/port.rs:196 |
| `rating1c` | `signXml(storage,keyType,xml,tbsXPath,parentXPath,BIN)` | **supported** | template: storage=PKCS12, keyType=SIGNATURE, BIN=''; bound cert must pass the plugin's validity check (expired -> error) | keys_select (+keys_terminals for token storages), keys_sign_xml_ex | xml_ex; via legacy::sign_xml: no tbs -> placement DocumentElement; tbs+parent -> Parent (XPath params); strip_whitespace, no line breaks, no declaration | 1 | no | no | bound (xml arg 2) | W+S+T: rating1c/src/port.rs:213, common/legacy/src/guest.rs:37, oncl-port-tests/tests/clones.rs:214 |
| `rating1c` | `signXmls(storage,keyType,xmls[],...)` | **unsupported** | `MULTI` | as signXml | xml_ex; as signXml per document | N=len(xmls) | no | no | bound | W+S: rating1c/src/port.rs:222 |
| `rating1c` | `createCmsFromBase64(storage,keyType,b64,attached,withTSA,BIN)` | **supported*** |  | keys_select, keys_sign_cms_ex | cms_ex; encapsulate=attached(param), cosign=Auto via Default (coerce Never), ts=Kalkan iff withTSA, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64 arg 2) | W+S+T: rating1c/src/port.rs:244, rating1c/src/port.rs:236, common/legacy/src/lib.rs:149 |
| `rating1c` | `createCmsesFromBase64(storage,keyType,b64s[],...)` | **unsupported** | `MULTI` | as createCmsFromBase64 | cms_ex; per element | N=len(base64s) | no | no | bound | W+S: rating1c/src/port.rs:252 |
| `rating1c` | `createRawSignFromBase64(storage,keyType,b64,BIN)` | **supported** |  | keys_select, keys_sign_raw, cert_details | raw; raw signature of decoded base64 (SHA256withRSA for RSA, key's own for GOST) | 1 | no | no | bound (base64 arg 2) | W+S+T: rating1c/src/port.rs:281, rating1c/src/port.rs:266 |
| `rating1c` | `createRawsSignFromBase64(storage,keyType,b64s[],BIN)` | **unsupported** | `MULTI` | as createRawSignFromBase64 | raw; per element | N=len(base64s) | no | no | bound | W+S: rating1c/src/port.rs:291 |
| `simourg` | `salemAit` | **no-sign** |  | - | - | 0 | no | no | - | S: simourg/src/lib.rs:158 |
| `simourg` | `createCMSSignatureWithTspFromBase64[storage,keyType,b64,attached,fileNames]` | **unsupported** | `DIALOG`, `OPTIONS` | keys_select, dialog_choice (confirm window on EVERY signing), ca_list, ocsp_fetch, keys_sign_cms_ex | cms_ex; ESEDO attrs.extra incl. checked OCSP answer, encapsulate=attached, ts=Kalkan | 1 | no | no | bound data; attrs network-derived | W+S: simourg/src/lib.rs:223, simourg/src/lib.rs:307 |
| `simourg` | `createCMSForEsedo[storage,keyType,b64,-,fileNames]` | **unsupported** | `DIALOG`, `OPTIONS` | keys_select, dialog_choice, ocsp_fetch, keys_sign_cms_ex, tsp_stamp x2 | cms_ex + 2 stamps; ESEDO attrs.extra, Custom GOST TSA stamp then Kalkan stamp | 1 | no | no | bound data; attrs network-derived | W+S: simourg/src/lib.rs:359 |
| `skf` | `getBundleVersion` | **no-sign** |  | - | - | 0 | no | no | - | S: skf/src/lib.rs:249 |
| `skf` | `myLoadSlotList` | **no-sign** | `DIALOG` | keys_terminals, dialog_choice | - | 0 | no | no | - | W+S: skf/src/lib.rs:290 |
| `skf` | `myBrowseKeyStore` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: skf/src/lib.rs:336 |
| `skf` | `getKeys` | **no-sign** | `KEYS_OPEN` | keys_open (storage+path+password), http_request_ex (CA list) | - | 0 | no | WRITES STATE (Skf.key) | - | W+S: skf/src/lib.rs:520 |
| `skf` | `signXades(canSign,docNum,url,mime,session)` | **unsupported** | `STATE`, `KEYS_OPEN`, `DERIVED` | http_request_ex (document at url), ocsp_fetch, keys_sign_xades | xades; XAdES with options chosen by the plugin | 1 | no (http allow-list) | READS STATE (key from getKeys) | derived (document downloaded from url) | W+S: skf/src/lib.rs:723, skf/src/lib.rs:85 |
| `taxtech` | `version` | **no-sign** |  | - | - | 0 | no (UNDEFINED origin tolerated) | no | - | S: taxtech/src/lib.rs:105 |
| `taxtech` | `selectKey` | **no-sign** | `STATE` | keys_select | - | 0 | tolerant: origin None -> 'UNDEFINED' | WRITES STATE (static HOLDER) | - | W+S+T: taxtech/src/lib.rs:191, taxtech/src/lib.rs:147 |
| `taxtech` | `selectedKeyInfo` | **no-sign** | `STATE` | - | - | 0 | tolerant | READS STATE | - | W+S: taxtech/src/lib.rs:308 |
| `taxtech` | `reset` | **no-sign** |  | - | - | 0 | tolerant | clears state | - | S: taxtech/src/lib.rs:112 |
| `taxtech` | `sign {format xml\|cms\|raw, data, signingParams}` | **unsupported** | `STATE`, `MULTI`; fresh instance -> KEY_NOT_SELECTED | keys_sign_xml \| keys_sign_cms_ex \| keys_sign_raw | xml / cms_ex / raw; xml: default per document (N docs); cms: Digest if digested, cosign Auto/Never, ts Kalkan; raw: first doc | xml: N docs; cms/raw: 1 | tolerant: origin None -> 'UNDEFINED'; holder.origin must equal | READS STATE (HOLDER from selectKey, origin-bound) | bound | W+S+T: taxtech/src/lib.rs:317, oncl-port-tests/tests/medium.rs:170 |
| `thundercrypt` | `sign {keyType file\|token, dataForSign,...} (SignNLClass.sign or legacy top-level)` | **unsupported** | `DIALOG`, `KEYS_OPEN`, `OPTIONS` | dialog_password, keys_open, ocsp_fetch, crl_fetch, tsp_stamp, tsp_request, cms_verify, keys_sign_cms_ex, keys_chain, hash | cms_ex + stamp + LTA upgrade; ESEDO attrs.extra, Custom TSA, post-sign verification, optional B-LTA upgrade | 1 | no | no | bound data; attrs network-derived | W+S: thundercrypt/src/lib.rs:310, thundercrypt/src/lib.rs:397, thundercrypt/src/lib.rs:336 |
| `uchet` | `test` | **no-sign** |  | - | - | 0 | no | no | - | S: uchet/src/port.rs:127 |
| `uchet` | `getVersion` | **no-sign** |  | - | - | 0 | no | no | - | S: uchet/src/port.rs:132 |
| `uchet` | `getMessage` | **no-sign** |  | - | - | 0 | no | no | - | S: uchet/src/port.rs:137 |
| `uchet` | `getFilePath` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: uchet/src/port.rs:183 |
| `uchet` | `checkCMS` | **no-sign** | `FILE` | page_file_read, cms_verify | - | 0 | no | no | - | W+S: uchet/src/port.rs:217 |
| `uchet` | `checkCMSFromWeb` | **no-sign** |  | http_request_ex, cms_verify | - | 0 | relative_to_origin when the URL is relative | no | - | W+S: uchet/src/port.rs:227 |
| `uchet` | `signXml(storage,keyType,xml,tbs,parent)` | **unsupported** | `TERMINALS`; storage 'PKCS12' throws (Outcome::Thrown); any token storage hits keys::terminals -> [] -> STORAGE_EMPTY; only a 'JKS' storage name could pass, which depends on how the core matches `storages` against the bound key | keys_select, keys_terminals, keys_sign_xml_ex | xml_ex; as rating1c legacy::sign_xml | 1 | no | no | bound (xml arg 2) | W+S: uchet/src/port.rs:149, common/legacy/src/guest.rs:208 |
| `uchet` | `signXmlApi(keyPath,password,xml)` | **unsupported** | `KEYS_OPEN` | keys_open, keys_sign_xml_ex | xml_ex; whole document (declaration prepended by the plugin) | 1 | no | no | bound (xml arg 2) | W+S: uchet/src/port.rs:412, uchet/src/port.rs:429 |
| `uchet` | `signFile(4)` | **unsupported** | `KEYS_OPEN`, `DIALOG`, `FILE`, `DERIVED` | page_file_read, file_open_ex, dialog_password, keys_open, keys_terminals, ocsp_fetch (check_cert), keys_sign_cms_ex, page_file_write | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | derived (file read by page path) | W+S: uchet/src/port.rs:461, uchet/src/port.rs:475, uchet/src/port.rs:532 |
| `uchet` | `signFilePath(3)` | **unsupported** | `KEYS_OPEN`, `DIALOG`, `FILE`, `DERIVED` | page_file_read, file_open_ex, dialog_password, keys_open, keys_terminals, ocsp_fetch (check_cert), keys_sign_cms_ex, page_file_write | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | derived (file read by page path) | W+S: uchet/src/port.rs:469, uchet/src/port.rs:475, uchet/src/port.rs:532 |
| `uchet` | `signFileFromDiskAndSaveToDiskApi(signToken,filePath,fileDir,keyPath,keyPassword,storageName)` | **unsupported** | `KEYS_OPEN`, `FILE`, `DERIVED`, `HTTP`; vendor licence call: arbitrary http endpoint outside the PKI allow-list | http_request_ex (POST signToken to http://ncalayer.uchet.kz:8080), page_file_read, keys_open, ocsp_fetch, keys_sign_cms_ex, page_file_write | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | derived (file read by page path) | W+S: uchet/src/port.rs:687, uchet/src/port.rs:630, uchet/src/port.rs:475 |
| `uchet` | `signFileAndReturnBase64Api(signToken,fileBase64,keyPath,keyPassword,storageName)` | **unsupported** | `KEYS_OPEN`, `HTTP`; vendor licence call: arbitrary http endpoint outside the PKI allow-list; would also be blocked if the window allows only PKI network | http_request_ex (POST signToken to http://ncalayer.uchet.kz:8080), keys_open, ocsp_fetch (check_cert), keys_sign_cms_ex | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64 arg 1) | W+S: uchet/src/port.rs:702, uchet/src/port.rs:630, uchet/src/port.rs:601 |
| `uchet-esf` | `signXml {args:{pkcsPath,pkcsPassword,data}}` | **unsupported** | `KEYS_OPEN` | keys_open (page path + password), keys_sign_xml | xml; Core defaults, whole document | 1 | no | no | bound (data) | W+S: uchet-esf/src/lib.rs:70, uchet-esf/src/lib.rs:47 |
| `uchet-esf` | `signEsfList {args:{pkcsPath,pkcsPassword,esfList[]}}` | **unsupported** | `KEYS_OPEN`, `MULTI` | keys_open, keys_sign_raw xN | raw; raw per list item | N=len(esfList) | no | no | bound | W+S: uchet-esf/src/lib.rs:83 |
| `workspace` | `getKaztokenKeys` | **no-sign** | `DIALOG`, `KEYS_OPEN` | dialog_password, keys_terminals, keys_open | - | 0 | no | no | - | W+S: workspace/src/lib.rs:146 |
| `workspace` | `sign {files[],fileNames,isKaztoken,issuerCert,...}` | **unsupported** | `OPTIONS`, `MULTI` | keys_select, ocsp_fetch, keys_sign_cms_ex, tsp_stamp (attachments) | cms_ex + stamp; card: ESEDO attrs.extra + OCSP; each attachment: attached ESEDO attrs + Custom TSA; 1 + (files.len()-1) signatures | 1 + (len(files)-1) | no | RUNNING flag only | bound (base64 files) | W+S: workspace/src/lib.rs:93, workspace/src/lib.rs:258 |
| `xdox` | `CREATECMS {storageName,params:{ncaManifest}}` | **unsupported** | `ORIGIN` | keys_select, keys_terminals, pkix_path, keys_sign_cms_ex | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, std attrs | 1 | YES: origin must contain 'xdox.kz' (unanchored substring) | no | bound (ncaManifest text) | W+S+T: xdox/src/lib.rs:23, xdox/src/lib.rs:114, oncl-port-tests/tests/clones.rs:610 |
| `xdox` | `ADDSIGNERTOCMS {storageName,params:{ncaManifest,cms}}` | **unsupported** | `ORIGIN`, `COSIGN` | as CREATECMS | cms_ex; cosign=Into(page's cms), detached, only the new signer time-stamped | 1 | YES (as above) | no | bound manifest + page CMS | W+S+T: xdox/src/lib.rs:23, xdox/src/lib.rs:128 |

## 4. Сводка

### 4.1 Вердикты и причины

| Вердикт | Методов |
|---|---|
| supported | 2 |
| supported* | 13 |
| unsupported | 59 |
| no-sign | 92 |
| всего | 166 |

В колонке «первая» учтена первая, самая жёсткая причина строки; «всего» означает, что причина есть среди прочих; «единственная» означает, что метод заблокирован только ею (§4.4).

| Причина | первая | всего | единственная |
|---|---|---|---|
| `ORIGIN` | 15 | 15 | 6 |
| `DIALOG` | 9 | 12 | 0 |
| `KEYS_OPEN` | 13 | 21 | 6 |
| `STATE` | 8 | 10 | 3 |
| `OPTIONS` | 6 | 14 | 5 |
| `MULTI` | 5 | 14 | 5 |
| `FILE` | 1 | 7 | 0 |
| `DERIVED` | 1 | 16 | 1 |
| `COSIGN` | 0 | 1 | 0 |
| `HTTP` | 0 | 2 | 0 |
| `TERMINALS` | 1 | 1 | 1 |

### 4.2 Порты без пригодных методов

| Порт | главная причина | остальные |
|---|---|---|
| `acbank` | `DIALOG` | `MULTI`, `DERIVED` |
| `arta` | `STATE` | `FILE`, `DERIVED` |
| `bas` | `OPTIONS` |  |
| `buhta` | `ORIGIN` | `STATE`, `MULTI` |
| `devart` | `STATE` | `MULTI`, `OPTIONS` |
| `documentolog` | `DIALOG` | `KEYS_OPEN`, `DERIVED`, `OPTIONS` |
| `doodocs` | `KEYS_OPEN` | `STATE` |
| `eot` | `OPTIONS` |  |
| `eup` | `OPTIONS` |  |
| `ezsigner` | `FILE` | `DERIVED` |
| `idocs` | `OPTIONS` |  |
| `k2sign` | `ORIGIN` | `DERIVED`, `FILE` |
| `knp` | `ORIGIN` | `KEYS_OPEN` |
| `metadoc` | `KEYS_OPEN` | `OPTIONS`, `DIALOG` |
| `motiw` | `KEYS_OPEN` |  |
| `nursign` | `ORIGIN` | `MULTI`, `FILE`, `DERIVED` |
| `qoltanba` | `ORIGIN` |  |
| `simourg` | `DIALOG` | `OPTIONS` |
| `skf` | `STATE` | `KEYS_OPEN`, `DERIVED` |
| `taxtech` | `STATE` | `MULTI` |
| `thundercrypt` | `DIALOG` | `KEYS_OPEN`, `OPTIONS` |
| `uchet` | `KEYS_OPEN` | `FILE`, `DERIVED`, `DIALOG`, `HTTP`, `TERMINALS` |
| `uchet-esf` | `KEYS_OPEN` | `MULTI` |
| `workspace` | `OPTIONS` | `MULTI` |
| `xdox` | `ORIGIN` | `COSIGN` |

### 4.3 Порты с операциями

Порт получает операции, если у него есть хотя бы один пригодный метод (`supported` или `supported*`).

| Порт | Пригодные методы | Виды подписи | Условия |
|---|---|---|---|
| `rating1c` | `signXml`, `createCmsFromBase64`, `createRawSignFromBase64` | cms_ex; raw; xml_ex | шаблон: `storage=PKCS12`, `keyType=SIGNATURE`, `BIN=''`; сертификат должен пройти проверку срока в самом плагине |
| `dogovor24` | `signCMS` | cms_ex | ключ выбирается до чтения имени метода; плагин требует, чтобы в сертификате было EKU и не было clientAuth |
| `efactoring` | `text`, `xml` | cms_ex; xml_ex | XPath вводит пользователь, они показаны в согласии; окно повтора при ошибке недоступно |
| `energy` | `sign` | cms_ex | `dialog_message` только на путях ошибки, там вызов кончается трапом |
| `eproc` | `signXml` | xml (Core по умолчанию) | шаблон: `storageName=PKCS12` (без вызова терминалов), `keyType=SIGNATURE` (у ключа тип KNCA SIGNATURE) |
| `esf-osdkz` | `signPlainData` | raw | `raw` над текстом, текст показан в согласии; `auth` не объявлен (это вход, а не подпись документа) |
| `fhs` | `signXml`, `signText` | cms_ex; xml | `dialog_choice` только при ошибке |
| `market` | `text`, `xml` | cms_ex; xml_ex | `dialog_choice` только при ошибке |
| `qiwi` | `signXml` | xml_ex | две операции по алгоритму ключа (RSA-SHA256 и ГОСТ 2004), §6 |

Условия, общие для всех строк `supported*`:

- хост строит `request` с фиксированными необязательными параметрами: у energy `alias` не задаётся, `isDigested=false`, документ один; `storageName=PKCS12`, `keyType=SIGNATURE`, `BINControl=""`;
- привязанный пользователем ключ должен проходить фильтр плагина (`knca_types`, EKU), иначе `keys::select` вернёт `None` и порт ответит отменой;
- `cosign=Auto` заменяется на `Never`;
- текстовые параметры (XPath `element/parent` у efactoring, rating1c, eproc и текст у `text`-методов) показываются в согласии как введённые значения.

### 4.4 Что дало бы снятие отдельных причин

Метод разблокируется, если все его причины входят в снимаемый набор. Подсчёт по строкам `unsupported` таблицы §3. Текущая модель эти причины не снимает.

| Сценарий | Разблокируется методов | Какие |
|---|---|---|
| снять `OPTIONS`: профиль «ESEDO», где Core сам строит `attrs.extra` по именам файлов и OCSP (хост знает и то и другое) | 5 | `bas.sign`, `dogovor24.signEsedo`, `eot.signCmsWithSignedAttrs`, `eup.sign`, `idocs.sign` |
| `keys::open` отвечает привязанным ключом (путь/пароль игнорируются) | 6 | `fhs.signTextV2`, `fhs.signXmlV2`, `metadoc.signXml`, `motiw.sign`, `uchet.signXmlApi`, `uchet-esf.signXml` |
| держать экземпляр между вызовами сессии ручного окна (снять `STATE`) | 3 | `arta.signBase64File`, `arta.signDocument`, `arta.signXML` |
| разрешить `MULTI` (несколько подписей, одно согласие) | 5 | `dogovor24.batchSignCMS`, `esf-osdkz.signPlainDataMap`, `rating1c.signXmls`, `rating1c.createCmsesFromBase64`, `rating1c.createRawsSignFromBase64` |
| `ORIGIN`: невозможно, Origin не подставляется | 6 | `buhta.call#2`, `nursign.text`, `nursign.binary`, `nursign.xml`, `qoltanba.signFileBytes`, `xdox.CREATECMS` |
| `keys::open` + `OPTIONS` | 11 | `bas.sign`, `dogovor24.signEsedo`, `eot.signCmsWithSignedAttrs`, `eup.sign`, `fhs.signTextV2`, `fhs.signXmlV2`, `idocs.sign`, `metadoc.signXml`, `motiw.sign`, `uchet.signXmlApi`, `uchet-esf.signXml` |
| `STATE` + `MULTI` | 9 | `arta.signBase64File`, `arta.signDocument`, `arta.signXML`, `dogovor24.batchSignCMS`, `esf-osdkz.signPlainDataMap`, `rating1c.signXmls`, `rating1c.createCmsesFromBase64`, `rating1c.createRawsSignFromBase64`, `taxtech.sign` |

Сценарий с `OPTIONS` объединяет разные варианты ЭСЭДО (разные формы времени, DN, OCSP, `econtent_type`, `Digest`), то есть набор профилей, а не один. Подмена `keys::open` привязанным ключом меняет смысл пароля и пути, которые присылает страница, а в ручном окне страницы нет. Сохранение экземпляра (`STATE`) противоречит F1 и правилу, что согласие не переживает вызов. `MULTI` даёт только списочные варианты уже пригодных методов.

Содержимое, которое плагин вычисляет сам (`DERIVED`), есть у 16 методов, и только `fhs.signFile` заблокирован одной этой причиной. Он подписывает документ, скачанный по адресу страницы через `http_request_ex`, а тот же результат даёт `fhs.signText` с файлом пользователя. Подпись вычисленной плагином строки JWS у `acbank` заблокирована ещё `DIALOG` и `MULTI`. Поэтому `derived` в ручном окне не поддерживается, а операции портов объявлены только для `bound`.

## 5. Воспроизведение

```text
cd plugins
cargo build --release --locked --target wasm32-unknown-unknown --workspace      # 34 модуля
python ../scripts/mp0_wasm_imports.py <CARGO_TARGET_DIR>/wasm32-unknown-unknown/release          # импорты по портам
python ../scripts/mp0_wasm_imports.py <CARGO_TARGET_DIR>/wasm32-unknown-unknown/release --json   # то же, JSON
cargo test -p oncl-port-tests --test clones --test ecc --test medium            # существующие тесты портов (корень репозитория)
```

Строки таблицы §3 получены чтением исходников (уровень **S**); ссылка `файл:строка` указывает на функцию или константу, от которой зависит вердикт. Для сверки откройте ссылку и убедитесь, что диспетчер приводит к этой функции, а перечисленные импорты есть в секции импортов порта.

## 6. Объявленные операции портов

### 6.1 Форма запроса

Что читает диспетчер каждого порта с операциями. Шаблон `[[operations]]` выражает все эти формы: `args` массивом, объектом или поля в корне.

| Порт | Методы | Что читает порт (файл:строка) | Форма запроса |
|---|---|---|---|
| `rating1c` | `signXml`, `createCmsFromBase64`, `createRawSignFromBase64` | `legacy::dispatch` — `rating1c/src/port.rs:66-72`, аргументы по `Param` — `:23-28` | `{"module":…,"method":"createCmsFromBase64","args":["PKCS12","SIGNATURE","<b64>",false,true,""]}`: `args` — массив из 6 (4 у raw) элементов, строки и булевы |
| `dogovor24` | `signCMS` | `dogovor24/src/lib.rs:76-81` (корень: `method`), `:131-132` (`args` — массив, `args[0]` — base64), `:104` (`uuid` в корне, только `signEsedo`) | `{"module":…,"method":"signCMS","args":["<b64>"]}` |
| `qiwi` | `signXml` | `qiwi/src/lib.rs:39-47` (`method`, `args` — массив, `args[0]` — callId), `:129` (`args[1]` — xml) | `{"module":…,"method":"signXml","args":["<callId>","<xml>",…]}` |
| `fhs` | V1 `signXml`, V1 `signText` | `fhs/src/lib.rs:55-66` → `oncl_protocol::invoker::java` `invoke_with` — `crates/oncl-protocol/src/invoker/java.rs:125-141` (`parse_only(["apiVersion","class","method","args"])`, `args` — `optJSONObject`), `:173-176` (нет объекта `args` → «`<method>` demands arguments»), поля — `fhs/src/lib.rs:480-519` | `{"module":…,"method":"signXml","args":{"xml":"<xml>"}}`; `signText`: `"args":{"base64data":"<b64>"}` |
| `energy` | `sign` | `energy/src/lib.rs:29-42` (корень: `method`; `args` — `get_object`), `:160-181` (`alias`, `keyStoreType`, `encapsulate`, `isDigested`, `tsaProfile` — булевы; `data` — массив объектов `{id,name,base64}`) | `{"module":…,"method":"sign","args":{"encapsulate":true,"isDigested":false,"tsaProfile":true,"data":[{"id":"1","name":"f","base64":"<b64>"}]}}` |
| `eproc` | `signXml` | `eproc/src/lib.rs:85-98` (корень: `method`), `:111` (`uid`), `:129-139` (`chain`, `storageName`, `keyType`, `xml`, `tbsElementXPath`, `signatureParentElementXPath`) | `{"module":…,"method":"signXml","uid":"…","storageName":"PKCS12","keyType":"SIGNATURE","xml":"<xml>","tbsElementXPath":"…","signatureParentElementXPath":"…"}`, `args` нет |
| `efactoring` | `text`, `xml` | `efactoring/src/lib.rs:38-52` (корень: `type`, не `method`), `:65-67` (`data`, `attach`, `has_timestamp` — булевы), `:91-102` (`source`, `sign_element`, `signature_parent_element`) | `{"module":…,"type":"text","data":"<text>","attach":false,"has_timestamp":true}`; `{"module":…,"type":"xml","data":"<xml>","sign_element":"…","signature_parent_element":"…"}` |
| `market` | `text`, `xml` | `market/src/lib.rs:32-46` (корень: `type`), `:60-62` (`data`, `attach`, `has_timestamp`), `:87` | как у `efactoring` |
| `esf-osdkz` | `signPlainData` | `esf-osdkz/src/lib.rs:37-61` (корень: `method`, `storageName`, `data`; `args` нет) | `{"module":…,"method":"signPlainData","storageName":"PKCS12","data":"<text>"}` |

### 6.2 Особенности операций

- `rating1c`: 7 операций. Документ для XML передаётся текстовым параметром (`xml`, не больше 65 536 знаков), потому что `document` в шаблоне всегда base64, а порт ждёт текст. Подпись элемента требует атрибута `Id` у подписываемого элемента (Kalkan: «Указанный для подписи элемент не содержит атрибут 'Id'»). У CMS `attached` и `withTSA` это поля профиля, поэтому операций четыре: `create-cms`, `create-cms-attached`, `create-cms-timestamp`, `create-cms-attached-timestamp`. `signXml` разбит на `sign-xml` (весь документ) и `sign-xml-element` (элемент в родителе, XPath текстовыми параметрами). Операции используют `keys_select`, `keys_release`, `random`, `cert_info`, `now` (у raw ещё `cert_details`); без любого из них вызов отказывает (`Denied`), а без `keys_release` уже после применения ключа. Проверено удалением каждого импорта.
- `energy`, `efactoring`, `market`: `attach`/`encapsulate` и `has_timestamp`/`tsaProfile` это поля профиля, поэтому у каждого порта четыре CMS-операции (`sign-cms-*` у energy, `sign-text-*` у efactoring и market): с данными внутри или отсоединённая, с меткой времени или без. У energy фиксированы `id=1` и `name=document`, `alias` и `keyStoreType` не задаются.
- `dogovor24`: одна операция `sign-cms` (данные внутри, метка времени Kalkan); из импортов кроме ключевых нужен `cert_info` для проверки EKU.
- `eproc`: две операции (весь документ и элемент); `uid` фиксирован как `manual`, `chain` не задан. Порт объявляет `keys_release`: при успехе ключ остаётся в `CHAIN`, но любой отказ порта после выбора ключа (например, `tbs` равен `parent`) отпускает ключ в `Drop`, и без импорта ответ порта с кодом 500 терялся бы в `Denied` (тест `a_failure_after_the_key_is_the_ports_error_reply`).
- `esf-osdkz`: операция `sign-plain-data`, запрос `{"method","storageName":"PKCS12","data"}` в корне, `raw` над UTF-8-байтами текстового параметра. Core отказывает (`InvalidValue`) на управляющих, bidi и невидимых символах, кроме `\n` и `\t`. Ключ должен проходить фильтр порта `KNCA=SIGNATURE`. Опций у `raw` нет.
- `fhs`: `sign-xml` (профиль по умолчанию) и `sign-text` (`cms_ex`, отсоединённая, `timestamp = "kalkan"`, `cosign` `Auto` заменяется на `never`), `args` объектом. Окно повтора (`dialog_choice`) у порта появляется только при ошибке; в ручном окне диалогов нет, поэтому при ошибке повтора не будет, что записано в `label` и комментарии манифеста.
- `qiwi`: порт передаёт в `keys_sign_xml_ex` `transforms = [Enveloped, C14N-with-comments]` и берёт адреса алгоритмов из сертификата ключа. XML-профиль задаёт `transforms` (поле 12 канонической кодировки пишется только когда задано, поэтому хеши остальных операций от него не зависят). Объявлены `sign-xml-rsa` и `sign-xml-gost2004`, по одной на алгоритм ключа; ключ другого алгоритма даёт `options-mismatch` до применения. Ключи ГОСТ 2015 (порт шлёт им адреса ГОСТ 2004) и RSA-SHA1 (его нет в `SIGNATURE_METHODS`) не поддерживаются. Тесты `plugin_ports_manual/qiwi.rs`.
- `efactoring.sign-xml-element`: XPath элемента и родителя вводит пользователь, оба видны на странице подтверждения. Пустой или не абсолютный `parent` хост отклоняет до запуска плагина; `parent`, равный элементу, порт отклоняет до применения ключа, и вызов кончается `Denied`, потому что окна повтора нет. Тесты `plugin_ports_manual/efactoring.rs`.
- Сеть: любая подпись в окне проверяет подписанта по OCSP (GET к ответчику из сертификата), а метка времени идёт к `tsp.pki.gov.kz`. При `network = "none"` вызов отказывает `PermissionDenied` до применения ключа, поэтому операция с `uses.key` обязана объявлять `network = "pki"`, и парсер отвергает сочетание `none` с `uses.key` (`plugin_ports_manual/network.rs`). TSA Kalkan (`TsaChoice::Kalkan`) ходит методом GET (`http://tsp.pki.gov.kz/<base64-запрос>`), поэтому эндпоинты PKI разрешают GET и POST и для OCSP, и для TSA.

Ключи ГОСТ проверены только в `qiwi.sign-xml-gost2004`; остальные операции проверены ключами RSA.

## 7. Настройки хоста для вызова портов

- Пределы ручного окна задаёт одно определение `oncl_core::plugins::ManualLimits::desktop()`; им пользуются и рабочий стол, и тесты. На 64-разрядной системе: документ до 4 МиБ, передача 9 МиБ, память гостя 112 МиБ, бюджеты 704 и 896 МиБ. Обоснование и измерения в `docs/dev/plugins-manual-tests.md`. Нехватка бюджета отказывает до ключа подкодом `resource-budget`, отсутствие временного хранилища у XML-операции подкодом `no-temporary-store`.
- Значения по умолчанию для этого не годятся. `InstanceLimits::default()` (память 1 ГиБ, передача 256 МиБ) вместе с `ResourceLimits::default()` даёт `Processing(MemoryLimit)` у любого порта: вызов резервирует `8 × max_transfer + max_memory` из бюджета памяти 1 ГиБ. XML-подпись Kalkan резервирует около 61 МиБ бюджета METADATA при бюджете по умолчанию 64 МиБ, и без увеличения вызов кончается `AfterKeyUse(MetadataLimit)`: ключ применён, ответа нет. XML-операциям также нужен `EngineServices::with_temporary_store`.
- `PluginRegistry::install` компилирует модуль через `oncl_plugin::Engine::eager()`: все функции переводятся при компиляции. Headless- и ручные вызовы подают топливо кусками по 100 000, а Wasmi при ленивом переводе списывает перевод функции с топлива первого вызова; нехватка топлива на переводе не возобновляется. `oncl_process` любого реального порта переводится дороже 100 000, поэтому с ленивым движком вызов падал бы с `OutOfFuel`. Интерактивный `Engine::new()` остаётся ленивым. Тест: `headless::tests::an_entry_function_costing_more_than_a_slice_to_translate_runs_in_an_eager_engine`.
- Эндпоинты OCSP и TSA в `NCA_PKI_ENDPOINTS` разрешают GET и POST.
