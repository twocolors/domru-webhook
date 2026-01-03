# domru-webhook

Прокси‑сервис для пересылки входящих вызовов домофона Dom.ru в webhook

Это надстройка над решением [domru](https://github.com/moleus/domru) (спасибо @moleus), которая позволяет отправлять событие входящего вызова с домофона в указанный webhook

---

## Предупреждение

**!!! ВНИМАНИЕ !!!**

В консоли/дебаг‑логах могут присутствовать логин и пароль. **Никому не передавайте эти данные** и не публикуйте в открытом доступе

---

## Возможности

* Преобразование события входящего вызова в HTTP‑запрос (webhook)
* Простая настройка через переменные окружения
* Запуск в Docker

---

## Настройка

### Переменные окружения (ENV)

```
DOMRU_URL   - URL Domru для получения авторизационных данных
WEBHOOK_URL - URL на который отправляется webhook (HTTP POST)
DEBUG       - Включение дебага (true/false, по умолчанию false)
PORT        - Локальный UDP‑порт (по умолчанию 5060)
IP          - Локальный IP (по умолчанию auto)
```

---

## Webhook

При входящем вызове на URL, указанный в `WEBHOOK_URL`, отправляется JSON‑запрос

**Пример запроса:**

```json
{
  "event": "Ringing"
}
```

---

## DOMRU_URL

Необходимо указать ссылку на web [domru](https://github.com/moleus/domru)

```
DOMRU_URL=http://192.168.0.10:18000/
```

---

## Установка

### Docker

```bash
docker pull ghcr.io/twocolors/domru-webhook
```

### Docker Compose

```yaml
services:
  domru-webhook:
    image: ghcr.io/twocolors/domru-webhook:latest
    container_name: domru-webhook
    hostname: domru-webhook
    restart: always
    environment:
      - TZ=Europe/Moscow
      - DOMRU_URL=http://192.168.0.10:18000/
      - WEBHOOK_URL=http://webhook.example
      - PORT=5060
      - DEBUG=false
    ports:
      - "5060:5060/udp"
```

---

## Примечания

* Контейнер должен иметь доступ к Domru API
* UDP‑порт `PORT` должен быть открыт и не занят другим сервисом
