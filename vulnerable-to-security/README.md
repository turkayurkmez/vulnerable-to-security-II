# VulnerableIssuerAPI

> ⚠️ **UYARI:** Bu proje, güvenlik eğitimi amacıyla kasıtlı olarak zafiyetler içermektedir. **Production ortamında kesinlikle kullanmayınız.**

Ödeme sistemleri güvenliği eğitimi için geliştirilmiş, bilerek güvensiz bırakılmış bir REST API. PCI DSS, OWASP API Top 10 ve JWT güvenliği konularını pratik örneklerle göstermek amacıyla tasarlanmıştır.

---

## İçindekiler

- [Gereksinimler](#gereksinimler)
- [Uygulamayı Ayağa Kaldırma](#uygulamayı-ayağa-kaldırma)
- [Varsayılan Kullanıcılar](#varsayılan-kullanıcılar)
- [Endpoint Listesi](#endpoint-listesi)
  - [Auth](#auth-apiaauth)
  - [Cards](#cards-apicards)
  - [Transactions](#transactions-apitransactions)
  - [Account](#account-apiaccount)
  - [Debug](#debug-_debug)

---

## Gereksinimler

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Git

---

## Uygulamayı Ayağa Kaldırma

### 1. Repoyu Klonla

```bash
git clone https://github.com/turkayurkmez/vulnerable-to-security-II.git
cd "vulnerable-to-security-II/Group 2/vulnerable-to-security"
```

### 2. Bağımlılıkları Yükle

```bash
dotnet restore
```

### 3. Uygulamayı Başlat

```bash
cd VulnerableIssuerAPI
dotnet run
```

Uygulama varsayılan olarak aşağıdaki adreslerde çalışır:

| Protokol | Adres |
|----------|-------|
| HTTP | `http://localhost:5000` |
| HTTPS | `https://localhost:5001` |

> Veritabanı (SQLite) uygulama ilk başlatıldığında otomatik olarak oluşturulur ve seed data yüklenir.

### 4. API Dokümantasyonu (Scalar UI)

Uygulama çalıştıktan sonra tarayıcıdan erişin:

```
https://localhost:5001/scalar
```

---

## Varsayılan Kullanıcılar

Uygulama başlarken aşağıdaki kullanıcılar otomatik olarak oluşturulur:

| Kullanıcı Adı | Şifre | Rol |
|---------------|-------|-----|
| `ahmet.yilmaz` | `password123` | user |
| `fatma.kaya` | `password123` | user |
| `admin` | `admin123` | admin |

---

## Endpoint Listesi

### Auth (`/api/auth`)

| Method | Endpoint | Auth | Açıklama |
|--------|----------|------|----------|
| `POST` | `/api/auth/login` | ❌ | Kullanıcı girişi, JWT token döner |
| `POST` | `/api/auth/otp/send` | ❌ | Belirtilen kullanıcıya OTP kodu gönderir |
| `POST` | `/api/auth/otp/verify` | ❌ | OTP kodunu doğrular |
| `POST` | `/api/auth/forgot-password` | ❌ | Şifre sıfırlama token'ı oluşturur |
| `POST` | `/api/auth/reset-password` | ❌ | Token ile yeni şifre belirler |

#### `POST /api/auth/login`

```json
{
  "username": "ahmet.yilmaz",
  "password": "password123"
}
```

#### `POST /api/auth/otp/send`

```json
{
  "userId": 1,
  "purpose": "login"
}
```

#### `POST /api/auth/otp/verify`

```json
{
  "userId": 1,
  "otpCode": "123456",
  "purpose": "login"
}
```

#### `POST /api/auth/forgot-password`

```json
{
  "email": "ahmet.yilmaz@example.com"
}
```

#### `POST /api/auth/reset-password`

```json
{
  "token": "<reset_token>",
  "newPassword": "yeniSifre123"
}
```

---

### Cards (`/api/cards`)

> 🔒 Tüm endpoint'ler `Authorization: Bearer <token>` gerektirir.

| Method | Endpoint | Auth | Açıklama |
|--------|----------|------|----------|
| `GET` | `/api/cards` | ✅ | Tüm kartları listeler |
| `GET` | `/api/cards/{id}` | ✅ | Belirtilen kartın detaylarını getirir |
| `GET` | `/api/cards/{id}/balance` | ✅ | Kartın bakiye bilgisini getirir |

---

### Transactions (`/api/transactions`)

| Method | Endpoint | Auth | Açıklama |
|--------|----------|------|----------|
| `POST` | `/api/transactions/authorize` | ❌ | İşlem yetkilendirmesi yapar |
| `GET` | `/api/transactions` | ❌ | Tüm işlemleri listeler |
| `GET` | `/api/transactions/search?query=` | ❌ | İşlemlerde metin bazlı arama yapar |
| `GET` | `/api/transactions/{id}` | ✅ | Belirtilen işlemin detaylarını getirir |

#### `POST /api/transactions/authorize`

```json
{
  "cardNumber": "4111111111111111",
  "cvv": "123",
  "expiryMonth": 12,
  "expiryYear": 2027,
  "amount": 150.00,
  "currency": "TRY",
  "merchantId": "MERCHANT_001",
  "description": "Alışveriş"
}
```

---

### Account (`/api/account`)

> 🔒 Tüm endpoint'ler `Authorization: Bearer <token>` gerektirir.

| Method | Endpoint | Auth | Açıklama |
|--------|----------|------|----------|
| `GET` | `/api/account/profile/{userId}` | ✅ | Kullanıcı profil bilgilerini getirir |
| `GET` | `/api/account/cards/{userId}` | ✅ | Kullanıcıya ait kartları listeler |

---

### Debug (`/_debug`)

> ⚠️ Authentication gerektirmeyen, production'da bulunmaması gereken debug endpoint'leri.

| Method | Endpoint | Auth | Açıklama |
|--------|----------|------|----------|
| `GET` | `/_debug/info` | ❌ | Ortam değişkenleri, connection string ve sistem bilgisi döner |
| `GET` | `/_debug/users` | ❌ | Tüm kullanıcıları şifre hash'leriyle listeler |
| `GET` | `/_debug/health` | ❌ | Uygulama sağlık durumu ve DB bilgileri döner |
| `POST` | `/_debug/execute-sql` | ❌ | Gönderilen SQL sorgusunu doğrudan çalıştırır |

#### `POST /_debug/execute-sql`

```json
"SELECT * FROM Users"
```

---

## Güvenlik Açıkları (Eğitim Amaçlı)

Bu projede kasıtlı olarak bırakılan başlıca açıklar ve mevcut düzeltme durumları:

### ✅ Düzeltilen Açıklar

| Açık | İlgili Kod | Düzeltme |
|------|-----------|----------|
| Negatif / sıfır tutar kabulü | `AuthorizationService.ProcessAsync` | `amount <= 0` kontrolü eklendi, geçersiz tutar reddediliyor |
| Maksimum tutar kontrolü yok | `AuthorizationService.ProcessAsync` | 100.000 TL üzeri işlemler engelleniyor |
| Kart vade tarihi kontrolü yok | `AuthorizationService.ProcessAsync` | Süresi dolmuş kartlar artık reddediliyor |
| Tahmin edilebilir transaction ID (`TXN000001`, `TXN000002`...) | `AuthorizationService.ProcessAsync` | UUID tabanlı rastgele ID ile değiştirildi (`TXN{8-char-guid}`) |

### ⚠️ Açık Kalan Zafiyetler

| Açık | İlgili Endpoint | CVSS |
|------|----------------|------|
| SQL Injection | `GET /api/transactions/search` | 10.0 |
| Arbitrary SQL Execution | `POST /_debug/execute-sql` | 10.0 |
| Sensitive Data Exposure (env vars, connection string) | `GET /_debug/info` | 10.0 |
| JWT Algorithm Confusion (`alg:none`) | Tüm korumalı endpoint'ler | 9.1 |
| Weak JWT Secret (hardcoded) | `POST /api/auth/login` | 9.1 |
| IDOR - Kart bilgilerine yetkisiz erişim | `GET /api/cards/{id}` | 8.1 |
| IDOR - Kullanıcı profili | `GET /api/account/profile/{userId}` | 6.5 |
| OTP/Token response'da açık gönderim | `POST /api/auth/otp/send`, `POST /api/auth/forgot-password` | 8.1 |
| Full PAN + CVV yetkilendirme response'unda | `POST /api/transactions/authorize` | 8.1 |
| MD5 ile şifre hashleme (PCI DSS ihlali) | `POST /api/auth/login` | - |
| Pagination eksikliği (DoS riski) | `GET /api/transactions` | - |
| CORS tamamen açık | Tüm endpoint'ler | - |
| Fraud detection / velocity check yok | `POST /api/transactions/authorize` | - |
