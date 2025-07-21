# Spring JWT Auth

![Java](https://img.shields.io/badge/Java-17%2B-blue?style=flat-square)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen?style=flat-square)
![Thymeleaf](https://img.shields.io/badge/Thymeleaf-HTML5-orange?style=flat-square)

## Описание

**Spring JWT Auth** — это учебный проект на Spring Boot, демонстрирующий аутентификацию и авторизацию пользователей с помощью JWT, а также разграничение доступа по ролям (GUEST, PREMIUM_USER, ADMIN) с использованием Thymeleaf.

В проекте реализованы:
- Регистрация и вход пользователей
- Авторизация через JWT (статeless)
- Роли пользователей и разграничение доступа
- Защита страниц и API по ролям
- Простое оформление интерфейса с помощью Bootstrap


## Быстрый старт

### 1. Клонируйте репозиторий
```bash
git clone https://github.com/your-username/spring-jwt.git
cd spring-jwt
```

### 2. Настройте переменные окружения
В файле `src/main/resources/application.properties` укажите:
- `jwt.secret` — секретный ключ для подписи токенов (любая длинная строка)
- `jwt.access-token-expiration` — время жизни access-токена (например, 3600000 для 1 часа)
- `jwt.refresh-token-expiration` — время жизни refresh-токена

### 3. Соберите и запустите проект
Для Windows:
```bash
./mvnw.cmd spring-boot:run
```
Для Linux/Mac:
```bash
./mvnw spring-boot:run
```

### 4. Откройте в браузере
Перейдите по адресу: [http://localhost:8080](http://localhost:8080)

