# OffRoute

**Умное раздельное туннелирование для AmneziaVPN на macOS.**
Через VPN идут только заблокированные сайты — OffRoute находит их сам. Всё остальное, в том числе российские сайты, банки и госуслуги, открывается без VPN.

<p align="center"><img src="icon/app.png" width="128" alt="OffRoute"></p>

[English below](#english)

## Для кого

Для тех, кто на Mac с AmneziaVPN устал постоянно включать и выключать VPN: включил — открылись YouTube и Instagram, но перестали работать банк, Госуслуги и маркетплейсы; выключил — наоборот. С OffRoute VPN можно держать включённым всегда: заблокированное идёт через него, российское — без него.

## Что умеет

- **Сам находит заблокированные сайты** и пускает через VPN только их.
- **Не надо переподключать VPN** и перезапускать браузер: найденный сайт начинает работать через несколько секунд.
- **Telegram, Claude и YouTube** всегда идут через VPN.
- **Российские сайты** всегда идут без VPN.
- **Выключено** — весь трафик идёт через AmneziaVPN, как обычно.
- **Помнит найденные сайты.** Любой сайт можно убрать из списка.

## Требования

- Mac на Apple Silicon (M1 и новее), macOS 12 или новее.
- [AmneziaVPN](https://amnezia.org) с сайта (не из App Store), протокол **AmneziaWG**.

## Установка

1. Скачайте `OffRoute.pkg` из [Releases](../../releases).
2. Откройте его. Если macOS скажет «не удалось проверить разработчика», откройте «Системные настройки → Конфиденциальность и безопасность» и нажмите «Всё равно открыть».
3. Пройдите установку. Пароль администратора понадобится один раз.
4. Откроется окно OffRoute. Разрешите ему настроить AmneziaVPN.

После установки в строке меню появится значок шлема.

### Удаление

В окне OffRoute нажмите «Удалить службу» и перенесите приложение в корзину.

## Приватность

OffRoute работает только на вашем компьютере и никуда не отправляет ваши данные.

## Ограничения

- Работает только с AmneziaVPN (протокол AmneziaWG).
- Только Mac на Apple Silicon.

## Лицензия

[MIT](LICENSE). OffRoute не связан с командой AmneziaVPN.

---

## English

Tired of toggling the VPN on and off on your Mac all day — on for blocked sites, off for local banking and shops? **OffRoute** is a split-tunneling companion for [AmneziaVPN](https://amnezia.org) on macOS: it finds blocked sites by itself and sends only them through the VPN; everything else goes direct. Telegram, Claude and YouTube always go through the VPN. Switched off, all traffic goes through the VPN as usual.

Requirements: Apple Silicon, macOS 12+, AmneziaVPN from amnezia.org with the AmneziaWG protocol. Install `OffRoute.pkg` from Releases. License: MIT.
