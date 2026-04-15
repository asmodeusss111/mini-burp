# Burp Scanner — Local Proxy

## Запуск

```bash
node server.js
```

Сервер запустится на http://localhost:8080

## Эндпоинты

| Метод | Путь | Описание |
|---|---|---|
| GET | `/proxy?url=https://site.com` | Универсальный прокси |
| POST | `/request` | Repeater — полный контроль |
| GET | `/portscan?host=site.com` | Реальное сканирование портов |
| GET | `/headers?url=https://site.com` | Все HTTP заголовки |

## Пример

```bash
# Сканировать порты
curl http://localhost:8080/portscan?host=example.com

# Получить заголовки
curl http://localhost:8080/headers?url=https://example.com

# Отправить запрос через repeater
curl -X POST http://localhost:8080/request \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","method":"GET","headers":{}}'
```

## Не нужен npm install — только Node.js!
