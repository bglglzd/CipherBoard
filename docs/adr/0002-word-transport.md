# ADR 0002: Word presentation over canonical ciphertext

- Status / Статус: accepted / принято
- Date / Дата: 2026-07-14
- Scope / Область: transport presentation, settings, parser limits, dictionaries

## English

### Context

Compact `CB1:` text is efficient and interoperable, but visibly resembles an
encoded payload. Users requested an optional Russian- or English-word rendering
for copying through ordinary messengers. This request concerns presentation,
not encryption: changing the Olm/Double Ratchet protocol or claiming covert
communication would increase risk and would be misleading.

The previous Universal/SMS selector mixed a core fragmentation choice with
transport presentation. CipherBoard is primarily used in messengers, and the
receiver does not need a different cryptographic protocol for SMS.

### Decision

All new sends use the existing universal 16-KiB Olm-payload fragmentation and
canonical `CB1:` envelope parts. After those exact ordered parts are built,
CipherBoard applies one sender-local presentation preference:

1. **Compact:** canonical `CB1:` parts separated by newline.
2. **Russian words:** `CBW1` Base4096 with the pinned Russian dictionary.
3. **English words:** `CBW1` Base4096 with the pinned English dictionary.

The SMS compact selector is removed from the UI and new-send path. Decode still
accepts old canonical `CB1` part sets produced with the 48-byte SMS profile.
Compact 0.4 output is interoperable with older CipherBoard releases. Both peers
must use CipherBoard 0.4 or newer for word presentation.

The preference affects future sends only. It is not stored per contact,
included in pairing, negotiated, or required to match the receiver's preference.
CipherBoard 0.4+ auto-detects compact, Russian-word, and English-word input.

### `CBW1` format

The word layer wraps the binary canonical CBOR bytes from every complete ordered
`CB1` part. Before Base4096, the wrapper is:

```text
tag[8] || "CBW" || version=1 || alphabet || flags=0 ||
part_count_be[2] || body_length_be[4] ||
repeat(part_length_be[4] || canonical_CB1_cbor_bytes)
```

The tag is placed first and equals the first eight bytes of
`SHA-256("CipherBoard Word Transport v1\0" || wrapper_without_tag)`. It is an
unkeyed corruption checksum, not a MAC and not sender authentication. The
wrapper is split most-significant-bit first into 12-bit values; each value
selects one of 4096 words. Decode verifies exact header values, length/count,
zero tail padding, tag, dictionary membership, and recovered canonical parts
before the unchanged Olm/AEAD authentication step.

`CBW1` names the internal magic/version and is not printed as a visible prefix.
The first external words encode the leading checksum bytes.

Limits are fixed at a 48-KiB decoded wrapper, 32,768 word tokens, and 384 Ki
UTF-16 code units at Android clipboard/selection boundaries. Exceeding any
limit fails before Vault access or unbounded allocation.

### Dictionaries and license

The version-1 lists are derived from `hermitdave/FrequencyWords`, commit
`525f9b560de45753a5ea01069454e72e9aa541c6`, files
`content/2018/en/en_50k.txt` and `content/2018/ru/ru_50k.txt`. Upstream content
and the generated derivatives are CC-BY-SA-4.0. Generation retains lowercase
alphabetic 4--10-letter words, deduplicates, removes profanity and alarming
words/fragments, and takes 4096 entries deterministically in frequency order.

- English SHA-256:
  `620b96da9c31f8552a6ed8eb54ef22a9a9a6b7885d2caf4ba9f658b748cf0cb3`
- Russian SHA-256:
  `6163eddf094c8c426959c1bb36d95dca3d7cbe4bdecc13bd13077279b7ccc8a9`

Changing a token or its order is a protocol change and requires a new word-
presentation version. Attribution is retained in `LICENSES.md` and
`THIRD_PARTY_NOTICES.md`.

### Security consequences

Olm session state, message keys, AEAD, forward secrecy, integrity, replay
handling, and authenticated inner/outer metadata are unchanged. Word rendering
therefore neither weakens nor strengthens those properties when decoded exactly.

It is only camouflage from casual inspection. The output is a sequence of
independent dictionary tokens, not a natural phrase, steganography, or plausible
deniability. Public dictionaries and deterministic structure make automated
detection and reversal possible. Word output is substantially longer than
compact `CB1`, exposes comparable transport metadata, and is more fragile under
autocorrect, translation, truncation, substitution, or token reordering.

### Alternatives rejected

- Natural grammar/synonym coding has low capacity, much greater expansion, and
  a larger unaudited parser/model surface.
- A bundled language model would increase APK size and reproducibility risk and
  still would not guarantee undetectable steganography.
- Zero-width characters and Unicode homoglyphs are routinely normalized or
  removed by transports.
- Replacing `CB1` cryptography with word-based encryption would be custom crypto
  and is prohibited.

## Русский

### Контекст и решение

Компактный `CB1:` эффективен, но внешне похож на кодированный блок. Для менее
заметного вида в обычном мессенджере добавлено необязательное представление
русскими или английскими словами. Это только способ записи уже готового
шифротекста, а не изменение Olm/Double Ratchet.

Все новые сообщения используют единое универсальное разбиение Olm-payload по
16 КиБ и канонические части `CB1`. После этого локальная настройка отправителя
выбирает компактный вид, русские слова или английские слова. Отдельный режим SMS
удалён из интерфейса и отправки. Приём старых `CB1`, созданных прежним SMS-
профилем, сохранён. Компактный вид совместим со старыми версиями, а для слов
CipherBoard 0.4+ нужен обоим участникам.

Настройка не привязана к контакту, не передаётся при сопряжении и не требует
совпадения на двух устройствах: версия 0.4+ определяет вид при чтении
автоматически.

### Формат и границы

`CBW1` упаковывает полный упорядоченный набор канонических `CB1`-частей. В
начале бинарной обёртки находится 8-байтовый усечённый SHA-256, затем magic
`CBW`, версия, алфавит, флаги, число частей, длина и сами части. Далее каждые
12 бит выбирают одно слово из зафиксированного словаря на 4096 слов.
Литералы `CBW1` снаружи не печатаются: первые видимые слова кодируют checksum.

Checksum не содержит ключа: его можно пересчитать, поэтому он только раньше
обнаруживает случайное повреждение и не аутентифицирует отправителя. Целостность
и подлинность по-прежнему проверяются неизменённым Olm/AEAD после строгого
восстановления `CB1`. Лимиты: 48 КиБ декодированной обёртки, 32 768 слов и
384 КиБ UTF-16 code units на Android-границе.

Словари получены из `hermitdave/FrequencyWords` по зафиксированному commit и
файлам, указанным выше, с лицензией CC-BY-SA-4.0. Преобразования и точные SHA-256
также перечислены выше; изменение порядка слов требует новой версии формата.

### Ограничения безопасности

Словарный вид не является естественной фразой, стеганографией или правдоподобным
отрицанием. Наблюдатель может распознать структуру и выполнить обратное
преобразование по публичному словарю. Такой текст значительно длиннее `CB1`, не
скрывает участников, время и примерный размер сообщения и легче повреждается
автозаменой, переводом, обрезанием, заменой или перестановкой слов.
