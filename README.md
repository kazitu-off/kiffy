
<p align="center">
  <h1 align="center">
    <code>⚡ KIFFY v2</code>
  </h1>
</p>

<p align="center">
  <code>Kiffy: Freedom to Communicate</code>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-00ff88?style=for-the-badge&logo=github"/>
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Rust-std--only-DEA584?style=for-the-badge&logo=rust"/>
  <img src="https://img.shields.io/badge/PHP-hosting-777BB4?style=for-the-badge&logo=php&logoColor=white"/>
  <img src="https://img.shields.io/badge/Tests-33%2F33-brightgreen?style=for-the-badge"/>
</p>

> **Минималистичный мессенджер без рекламы и слежки. Ваш сервер — ваши правила.**

## Что нового в v2

Версия 1 не могла работать в принципе: сервер шифровал сообщения ключом,
который никогда не покидал сервер, а клиент читал шифрованные байты как текст.
v2 — это переписанный с нуля проект:

- **Один порт — три транспорта**: TCP-чат (терминал), HTTP (лендинг, загрузки)
  и WebSocket (веб-приложение) на порту 8888 одновременно.
- **asyncio вместо потока на клиента** — тысячи соединений на одном потоке.
- **Framing-протокол** (4-байтовая длина + JSON): v1 читал сырой `recv()` и мог
  склеивать/рвать сообщения — классическая ошибка TCP.
- **Материальное веб-приложение** (`app.html`): Material You (MD3) — тон-палитры,
  navigation rail на десктопе, bottom bar на телефоне, **панель виджетов**
  (онлайн-чипы, адрес/шифрование/живая задержка, быстрые действия, тема), RU/EN.
- **Работает и на обычном PHP-хостинге** — приложение само переключается на
  long-polling, если WebSocket недоступен (`php-server/`).
- **Rust-версия сервера** без единого crate (`rust/`).
- Опциональное **PSK-шифрование** (`--psk`): пароль не передаётся по сети
  (HMAC challenge-response), ключ сессии выводится из пароля и nonce.

## Быстрый старт

### Python (рекомендуется, ноль зависимостей)

```bash
python3 kiffy_server.py                # порт 8888: чат + веб + websocket
python3 kiffy_client.py                # терминальный клиент
```

Откройте `http://localhost:8888/` — лендинг, `http://localhost:8888/app.html` — веб-чат.

### Rust (без cargo, без crates)

```bash
cd rust && ./build.sh                  # собирает ./kiffy_server чистым rustc
./kiffy_server --selftest              # проверка SHA/AES/HMAC/JSON векторов
./kiffy_server --port 8888
```

### Обычный PHP-хостинг (без Node/Python/БД)

Скопируйте `api.php`, `index.html`, `app.html`, `android.html`, `data/` в
`public_html` — детали в [`php-server/README.md`](php-server/README.md).
`app.html` при недоступности WebSocket сам переключится на long-polling
(бейдж `POLL` в виджете «Сервер»).

### Шифрование (опционально)

```bash
pip install cryptography
python3 kiffy_server.py --psk "наш-общий-секрет"      # сервер
python3 kiffy_client.py 127.0.0.1 --psk "наш-общий-секрет"
```
В веб-приложении укажите тот же пароль в диалоге подключения
(работает по HTTPS или на localhost — требование WebCrypto).

## Производительность

`python3 benchmark.py` (один CPU, один asyncio-поток):

```
ping-pong latency   : p50 0.11 ms   p95 0.23 ms   max 0.35 ms   (200 probes)
broadcast 100 peers  : 30000 msgs in 0.35s  =    85808 msg/s  (  8580754 deliveries/s)
broadcast 200 peers  : 60000 msgs in 1.20s  =    49798 msg/s  (  9959586 deliveries/s)
throughput 50x200   : 10000 msgs sent, 490000 deliveries complete: True,
                      3.72s  =   131720 deliveries/s sustained
concurrent sessions : 500 live connections in 4.39s
```

Почему быстрее v1: один event loop вместо потока на клиента; broadcast
сериализует/шифрует сообщение **один раз** и раздаёт готовые байты, не
блокируясь на медленных получателях (v1 отправлял blocking `send()` по кругу —
один медленный клиент тормозил всю комнату); O(1) token-bucket вместо
пересборки списков таймстемпов; отсутствие locks — всё состояние живёт на
потоке event loop.

## Команды

### Пользователи
```bash
/users            # кто онлайн
/s [user] [msg]   # личное сообщение
/anchor [user]    # все сообщения — только этому пользователю
/unanchor         # отпустить
/exit             # выйти
```

### Админ (имя `admin`)
```bash
/global [msg]     # объявление всем
/star [user]      # выдать звезду
/makeadmin [user] /removeadmin [user]
/ban [user] [reason] /unban [user] /banlist
/setemoji [emoji]
```
Пароль админа: спросит при старте, либо `--admin-password` / `KIFFY_ADMIN_PASSWORD`.

## Опции сервера

```bash
--port N                # или $PORT / $KIFFY_PORT
--psk <passphrase>      # шифрованный транспорт (нужен пакет cryptography)
--admin-password <pwd>  # или $KIFFY_ADMIN_PASSWORD
# лимиты: $KIFFY_RATE_CAP (всплеск, 30), $KIFFY_RATE_PER_SEC (0.5)
```

## Тесты

```bash
python3 test_kiffy.py     # 33 проверки: TCP, WS, HTTP, админ, баны, interop
python3 benchmark.py      # latency / fan-out / throughput / concurrency
```
CI (`.github/workflows/ci.yml`) гоняет тесты Python, `cargo test` +
`--selftest` Rust (векторы FIPS-197/RFC 4231) и `php -l` на каждый пуш.

## Архитектура

```
Один порт 8888
 ├── первый байт 0x00 → TCP-чат:  [4B длина][JSON]
 ├── "GET ..."      → HTTP:       /, /app.html, /android.html, загрузки
 └── "GET /ws"      → WebSocket:  веб-приложение (Material You)

Протокол (поле "t"): hello/welcome/msg/pm/pm_sent/global/sys/users/
typing/ping/pong/error/exit  — полная спецификация в docstring
kiffy_server.py и в MOBILE_APP_PROMPT.md
```

- **`kiffy_server.py`** — эталонный сервер (asyncio, ~700 строк, stdlib)
- **`kiffy_client.py`** — терминальный клиент (asyncio)
- **`rust/src/main.rs`** — сервер на чистом Rust (потоки + mpsc, crypto с нуля)
- **`app.html`** — веб-приложение Material You (один файл, без фреймворков)
- **`php-server/`** — бэкенд для shared-хостинга
- **`render-server.py`** — headless-точка входа для Render.com/PaaS
- **`MOBILE_APP_PROMPT.md`** — готовый промпт для ИИ: нативное Android-приложение

## Android

Готового APK нет — но есть два пути:

1. **Сейчас**: откройте `app.html` в мобильном браузере — интерфейс уже
   мобильный (bottom navigation, FAB, адаптивные виджеты).
2. **Нативное приложение**: отдайте [`MOBILE_APP_PROMPT.md`](MOBILE_APP_PROMPT.md)
   любой ИИ — она соберёт Kotlin/Compose Material 3 клиент по спецификации.

## License

MIT — делайте что хотите.

---

<p align="center">
  <code>Simple. Honest. Ad-free.</code>
</p>
