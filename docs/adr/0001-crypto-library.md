# ADR 0001: Криптографическая библиотека и Android-интеграция

- Статус: принято
- Дата: 2026-07-13
- Область: `crypto-core`, pairing, хранение состояния Olm, JNI

## Контекст

CipherBoard нужен одноранговый протокол для двух участников с уникальными
ключами сообщений, forward secrecy, DH-ratchet, поддержкой ограниченного числа
сообщений не по порядку и обнаружением повторной доставки. Приложение не имеет
сервера и сетевого разрешения, поэтому каталог ключей, доставка и доверие к
контакту должны быть реализованы поверх физического взаимного QR-сопряжения.

Самостоятельная реализация Double Ratchet, Curve25519, Ed25519, HKDF, MAC или
шифра не рассматривается. Криптографическое состояние должно переживать
остановку процесса без отката ratchet и не должно передаваться в JVM в открытом
виде без необходимости.

## Решение

Использовать чистую Rust-реализацию Olm из `matrix-org/vodozemac`:

| Параметр | Зафиксированное значение |
| --- | --- |
| Crate | `vodozemac` |
| Версия | `0.10.0` |
| Git tag | `0.10.0` |
| Git commit | `bb39ec65357989f975e0d47f9fb35e0656180151` |
| crates.io SHA-256 checksum | `b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b` |
| Minimum Rust version | `1.85` |
| Rust edition | `2024` |
| Лицензия | Apache-2.0 |

Зависимость задаётся точной, а `Cargo.lock` хранится в репозитории:

```toml
[dependencies]
vodozemac = { version = "=0.10.0", default-features = false, features = ["experimental-session-config"] }
```

Выбран только Olm для связи один-к-одному. Megolm и групповые сессии в версии 1
CipherBoard не используются.

### Конфигурация Olm

Все новые сессии CipherBoard используют `SessionConfig::version_2()`.
Согласование capability при QR-сопряжении обязано включать версию конфигурации
сессии. Устройство отклоняет:

- отсутствие поддержки V2;
- pre-key message с `SessionConfig::version_1()`;
- неизвестную обязательную версию протокола;
- попытку тихого понижения V2 до V1;
- сессию, созданную для другого Curve25519 identity key.

V1 использует HMAC, усечённый до 8 байт. V2 использует полный HMAC, но в
vodozemac 0.10.0 всё ещё помечен feature-флагом
`experimental-session-config`. Для собственного протокола, где оба конца
работают на одном APK, полный MAC важнее совместимости с legacy Matrix/libolm.
Экспериментальный статус V2 является известным остаточным риском и требует
отдельных interoperability, mutation и fuzz-тестов. Обновление vodozemac или
изменение session config требует нового ADR и явной миграции протокола.

### Feature-флаги и release blockers

Запрещено включать:

- default feature `libolm-compat`;
- `low-level-api`;
- `insecure-pk-encryption`;
- `js`;
- Megolm API;
- `cfg(fuzzing)` в production build.

`cfg(fuzzing)` в vodozemac преднамеренно отключает проверку MAC. Скрипт release
verification должен проверять Cargo/Rust flags и завершать сборку с ошибкой при
обнаружении `--cfg fuzzing`. `experimental-session-config` является
единственным разрешённым нестандартным feature-флагом vodozemac.

## Используемый API vodozemac

Минимальная обёртка использует только высокоуровневые API:

- `Account::new`, `identity_keys`, `sign`;
- `generate_one_time_keys`, `one_time_keys`, `mark_keys_as_published`;
- `Account::create_outbound_session`;
- `Account::create_inbound_session`;
- `Session::encrypt`, `Session::decrypt`;
- `OlmMessage::to_parts`, `OlmMessage::from_parts`;
- `AccountPickle`, `SessionPickle` и соответствующие `from_pickle`.

Числовой Olm message type из `OlmMessage::to_parts()` является обязательной
частью transport envelope. Входной parser сначала применяет лимиты CipherBoard,
а затем передаёт ограниченный массив байтов в `OlmMessage::from_parts()`.

Успешный `create_inbound_session()` одновременно расшифровывает первый pre-key
message, расходует локальный one-time key и возвращает новую сессию. Поэтому
новые `AccountPickle` и `SessionPickle`, replay record и pending display должны
фиксироваться одной транзакцией до показа plaintext.

Vodozemac ограничивает хранение skipped message keys: пять receiving chains,
до 40 ключей на chain и максимальный forward gap 2000. CipherBoard не повышает
эти лимиты через low-level API. Повтор уже использованного Olm message обычно
возвращает `MissingMessageKey`, однако дополнительно хранится постоянный
ограниченный replay ledger по случайному CipherBoard message ID.

## JNI-интеграция

Создаётся собственная небольшая Rust-библиотека `cdylib` с явно определённым
JNI-интерфейсом для `arm64-v8a` и тестового `x86_64`. Официальный репозиторий
`vodozemac-bindings` помечен как unmaintained и не используется. Полный
`matrix-sdk-crypto-ffi` также не включается: он приносит Matrix-specific state
machine, SQLite и существенно большую поверхность атаки.

Минимальная JNI-поверхность содержит операции:

1. создать identity и вернуть только публичные ключи и sealed account state;
2. создать одноразовый pairing key material;
3. создать outbound session и первый pre-key message;
4. создать inbound session из проверенного pairing response;
5. зашифровать bytes и вернуть Olm type, ciphertext и новое sealed state;
6. расшифровать ограниченный Olm message и вернуть plaintext и новое sealed
   state как единый результат;
7. вернуть точную версию crypto core для `BUILD_INFO.txt`.

Долгоживущие указатели на Rust-объекты не передаются в Kotlin и не переживают
process death. Каждая изменяющая состояние операция получает sealed state и
возвращает его следующую ревизию. JNI принимает и возвращает `ByteArray`, а не
строки, для plaintext, ключей и внутреннего состояния. Plaintext неизбежно
копируется Android UI/JNI, поэтому абсолютная zeroization в JVM не заявляется.

JNI-ошибки преобразуются в фиксированные коды без plaintext, ciphertext, QR
payload, contact name, fingerprint или session state. Нельзя форматировать
секретные типы через `Debug`. Panic не должен пересекать JNI boundary; наружу
возвращается общий безопасный код ошибки без panic message.

Android feasibility подтверждена официальным Matrix Rust SDK: его UniFFI crypto
bindings зависят от vodozemac, собираются как `cdylib/staticlib` и документируют
NDK cross-compilation для `aarch64-linux-android`. CipherBoard использует этот
факт как подтверждение платформы, но не переиспользует широкую обёртку SDK.

## Сериализация и защита состояния

`AccountPickle` и `SessionPickle` являются Serde-представлениями, но vodozemac
не обещает стабильный конкретный формат сериализации. Каждая запись CipherBoard
содержит собственные поля schema version, vodozemac version, session config и
монотонную локальную revision. Неизвестная версия не десериализуется как
текущая.

Встроенный encrypted pickle не является единственной защитой at rest. Его
реализация наследует детерминированное получение AES-CBC IV из pickle key и
8-байтовый MAC legacy pickle. Поэтому состояние дополнительно помещается в
аутентифицированную запись secure storage с новым случайным nonce и AAD,
включающим как минимум тип записи, внутренний contact ID, schema version и
revision. Ключ верхнего уровня защищается Android Keystore согласно политике
Vault. Повторное использование nonce запрещено и покрывается тестами.

Временные pickle keys, DEK и Rust-буферы оборачиваются в `Zeroizing` или явно
очищаются сразу после операции. Они не логируются и не включаются в panic/error
text. Копии, создаваемые Serde, JNI и Android UI, должны жить в минимальной
области видимости; гарантированное удаление всех копий из RAM не обещается.

### Атомарность отправки

Под блокировкой конкретной сессии:

1. загрузить и проверить текущую revision;
2. расшифровать sealed `SessionPickle`;
3. вызвать `Session::encrypt()`;
4. получить новую revision состояния и transport ciphertext;
5. одной транзакцией сохранить новое sealed state и pending ciphertext;
6. только после commit разрешить `InputConnection.commitText(ciphertext)`;
7. после успешной вставки отметить pending operation завершённой.

Если процесс завершается до commit базы, ciphertext не покидает приложение и
старая revision остаётся допустимой. Если процесс завершается после commit,
pending ciphertext восстанавливается без повторного вызова `encrypt()`.

### Атомарность получения

Под той же блокировкой сессии:

1. проверить envelope, routing tag, message ID и replay ledger;
2. загрузить текущую revision;
3. вызвать `Session::decrypt()` во временный буфер;
4. одной транзакцией сохранить новое sealed state, replay record и
   зашифрованный pending-display record;
5. показать plaintext только после commit;
6. удалить pending-display record после закрытия защищённого viewer.

Ошибка MAC, неверный identity/session tag, повтор или превышение skipped-key
лимита не должны изменять сохранённое состояние. Параллельные send/decrypt для
одного контакта сериализуются; optimistic revision check отклоняет устаревший
результат.

## Аудит и известные ограничения

Least Authority завершила единственный опубликованный аудит vodozemac
2022-03-30. Первоначально проверялся commit
`7c11a501bc316a0bf92a5fe06fee8582aad24897`, а при verification commit
`57d8d87a747653d6d7b7a53acb9a8d8f8de48285`.

В scope не входили:

- Android/Java, Python и JavaScript bindings;
- интеграция с приложением верхнего уровня;
- криптографический дизайн Olm и Megolm как таковой.

В финальном отчёте оставались нерешёнными:

- Issue I: ключи в памяти не защищены от чтения swap/memory и side-channel
  атак;
- Issue J: 64-битный MAC V1 короче рекомендованного;
- Suggestion 8: лимиты retained chain/message keys не настраиваются.

Версия 0.10.0 значительно новее проверенных commits. Ни она целиком, ни V2, ни
JNI-обёртка CipherBoard не проходили отдельный независимый аудит. Это должно
быть явно отражено в threat model и пользовательском разделе безопасности.

Официально опубликованы две low-severity advisory:

- GHSA-c3hm-hxwf-g5c6: ухудшенная zeroization в 0.5.0 и 0.5.1, исправлена в
  0.6.0;
- GHSA-j8cm-g7r6-hfpq / CVE-2024-40640: non-constant-time Base64 до 0.7.0,
  исправлена в 0.7.0.

Зафиксированная 0.10.0 не входит в указанные affected ranges. Перед каждым
release всё равно выполняются `cargo audit`, проверка GitHub security
advisories, SBOM и ручное сравнение новых upstream release notes.

## Лицензирование

Vodozemac распространяется под Apache-2.0. Apache-2.0 совместима с GPLv3, но не
с GPLv2-only. Комбинированный APK CipherBoard распространяется согласно GPLv3,
при этом текст Apache-2.0, copyright notices и notices всех транзитивных crates
сохраняются в исходной форме и включаются в third-party notices и SBOM.

## Отклонённые варианты

- Самописный Double Ratchet: неприемлемая криптографическая и аудиторская
  поверхность.
- `libolm`: legacy C/C++ реализация официально deprecated в пользу vodozemac.
- `matrix-org/vodozemac-bindings`: официальный репозиторий помечен unmaintained.
- Полный `matrix-sdk-crypto-ffi`: решает более широкую Matrix-задачу и нарушает
  принцип минимальной JNI-поверхности CipherBoard.
- Megolm: предназначен для групп и не даёт требуемой модели сессии один-к-одному.
- Неофициальный fork или плавающая Git dependency: не обеспечивает
  воспроизводимость и контролируемую проверку обновлений.

## Последствия

Положительные:

- криптографические примитивы и Double Ratchet не реализуются проектом;
- чистый Rust уменьшает площадь ошибок ручного управления памятью по сравнению
  с legacy C/C++;
- точная версия, checksum и lockfile дают воспроизводимую основу;
- V2 устраняет известный недостаток 64-битного message MAC для собственного
  протокола;
- минимальный JNI не приносит runtime network code и Google Play Services.

Отрицательные и остаточные:

- V2 имеет upstream-статус experimental;
- аудит 2022 года не покрывает текущую версию, bindings и интеграцию;
- защита памяти и zeroization ограничены Rust allocator, JNI и JVM;
- skipped-key limits могут сделать сильно задержанные сообщения
  нерасшифровываемыми;
- безопасность зависит от правильной QR-проверки transcript, Android Keystore,
  атомарного хранилища и отсутствия rollback, а не только от vodozemac.

## Первичные источники

- Официальный release 0.10.0 и signed tag:
  <https://github.com/matrix-org/vodozemac/releases/tag/0.10.0>
- Точный release commit:
  <https://github.com/matrix-org/vodozemac/commit/bb39ec65357989f975e0d47f9fb35e0656180151>
- Crates.io metadata API:
  <https://crates.io/api/v1/crates/vodozemac/0.10.0>
- Cargo manifest 0.10.0:
  <https://raw.githubusercontent.com/matrix-org/vodozemac/0.10.0/Cargo.toml>
- Официальная документация crate и pickling:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/>
- Olm Account API:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.Account.html>
- Olm Session API:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.Session.html>
- SessionConfig V1/V2:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.SessionConfig.html>
- Olm message transport parts:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/olm/enum.OlmMessage.html>
- Decryption and replay-related errors:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/olm/enum.DecryptionError.html>
- Реализация cipher, pickle MAC и специального `cfg(fuzzing)`:
  <https://matrix-org.github.io/vodozemac/src/vodozemac/cipher/mod.rs.html>
- Реализация сериализации и очистки pickle buffers:
  <https://matrix-org.github.io/vodozemac/src/vodozemac/utilities/mod.rs.html>
- Лимиты skipped message keys:
  <https://matrix-org.github.io/vodozemac/src/vodozemac/olm/session/receiver_chain.rs.html>
- Официальный security policy и advisories:
  <https://github.com/matrix-org/vodozemac/security>
- GHSA-c3hm-hxwf-g5c6:
  <https://github.com/matrix-org/vodozemac/security/advisories/GHSA-c3hm-hxwf-g5c6>
- GHSA-j8cm-g7r6-hfpq:
  <https://github.com/matrix-org/vodozemac/security/advisories/GHSA-j8cm-g7r6-hfpq>
- Least Authority audit report:
  <https://matrix.org/media/Least%20Authority%20-%20Matrix%20vodozemac%20Final%20Audit%20Report.pdf>
- Unmaintained official bindings:
  <https://github.com/matrix-org/vodozemac-bindings>
- Официальный Android cross-compilation precedent:
  <https://github.com/matrix-org/matrix-rust-sdk/tree/main/bindings/matrix-sdk-crypto-ffi>
- Vodozemac Apache-2.0 license:
  <https://github.com/matrix-org/vodozemac/blob/0.10.0/LICENSE>
- GPLv3/Apache-2.0 compatibility:
  <https://www.gnu.org/philosophy/license-list.html#apache2>
  и <https://www.apache.org/licenses/GPL-compatibility>
