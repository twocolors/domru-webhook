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
LOCAL_PORT  - Локальный UDP‑порт (по умолчанию 5060)
```

---

## Webhook

При входящем вызове на URL, указанный в `WEBHOOK_URL`, отправляется JSON‑запрос

**Пример тела запроса:**

```json
{
  "event": "Ringing"
}
```

---

## Получение DOMRU_URL

Необходимо получить ссылку для работы с API Domru

В конфигурации Domru (например, Home Assistant) используется следующий REST‑команд:

```yaml
rest_command:
    domru_open_door:
        url: http://127.0.0.1:18000/rest/v1/places/1234/accesscontrols/4321/actions
        method: post
        headers:
            accept: "application/json"
        content_type: 'application/json; charset=utf-8'
        payload: '{"name":"accessControlOpen"}'
```

На основе этих данных формируется путь

```
/rest/v1/places/{placeId}/accesscontrols/{accessControlId}/sipdevices
```

В приведённом примере значение переменной `DOMRU_URL` будет таким

```
DOMRU_URL=http://127.0.0.1:18000/rest/v1/places/1234/accesscontrols/4321/sipdevices
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
      - DOMRU_URL=http://127.0.0.1:18000/rest/v1/places/1234/accesscontrols/4321/sipdevices
      - WEBHOOK_URL=http://webhook.example
      - LOCAL_PORT=5060
      - DEBUG=false
    ports:
      - "5060:5060/udp"
```

---

## Безопасность

* Не публикуйте `DOMRU_URL`
* Отключайте `DEBUG` в продакшене
* Используйте HTTPS для `WEBHOOK_URL`

---

## Примечания

* Контейнер должен иметь доступ к Domru API
* UDP‑порт `LOCAL_PORT` должен быть открыт и не занят другим сервисом
