# LAMPA Pull

Android-приложение: вводишь claim-код из оплаты LAMPA VPN — оно само регистрирует устройство,
тянет подписанный манифест и раскладывает конфиги в файлы.

Без рута, без Play Integrity, без сторонних серверов: всё общение напрямую с control-plane.

## Что делает

1. `POST /v1/device/register` — ключ **EC P-256 (secp256r1)**, `pub_key` = SPKI DER в base64,
   тело `{code, brand:"lampa", pub_key, attestation:"none"}`.
2. `GET /v1/device/manifest` — подпись запроса
   `ECDSA-SHA256("<device_ref>\nGET\n/v1/device/manifest\n<epoch>")` в заголовках
   `X-Lampa-Device / X-Lampa-Timestamp / X-Lampa-Signature`.
3. Экспорт в `Android/data/net.erafox.lampapull/files/LAMPA-<дата>/`:
   - `manifest.json` — сырой подписанный манифест
   - `wg-<группа>.conf` — WireGuard/AmneziaWG по каждой egress-группе
   - `sing-box.json` — outbounds на все endpoint'ы (vless-reality, vless-xhttp,
     ss2022-shadowtls, hysteria2, tuic, trojan, anytls)
   - `links.txt` — те же узлы ссылками

## Важно про ключ

Приложение подписывается **ECDSA P-256**, не Ed25519. С Ed25519 сервер отвечает
`401 registration refused` на любой код — на этом легко потерять час.

Код одноразовый: успешный `register` его сжигает. Если ключ не сохранён до запроса —
код потрачен (`E_CLAIM_ALREADY_USED`), нужен новый.

## Сборка

Gradle не нужен. Нужны JDK 17, Android SDK (platform 34, build-tools 34.0.0) и BouncyCastle
`bcprov-jdk18on-1.78.1.jar` (только для X25519 WireGuard-ключей):

```bash
export JAVA_HOME=/path/to/jdk17
export ANDROID_HOME=/path/to/android-sdk
export BC_JAR=/path/to/bcprov-jdk18on-1.78.1.jar
./build.sh
```

Готовый APK: `release/LAMPA-Pull.apk` (подписан debug-ключом, ~1.7 МБ).

## Установка

```bash
adb install -r release/LAMPA-Pull.apk
```

Или открыть APK на телефоне (разрешить установку из неизвестных источников).

## Ограничения

- Конфиги живут, пока жива подписка: после отмены сервер снимает пир, `.conf` перестаёт подниматься.
- Приложение не продлевает подписку и не платит — только снимает то, что сервер отдаёт устройству.
- Debug-подпись: обновления из Play не встанут поверх, это отдельное приложение.
