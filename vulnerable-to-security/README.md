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
  - [Threat Modelling](#threat-modelling-apithreatmodelling)
- [Transaction State Machine](#transaction-state-machine)
- [Güvenlik Açıkları (Eğitim Amaçlı)](#güvenlik-açıkları-eğitim-amaçlı)
  - [STRIDE Analizi](#stride-analizi)
  - [Düzeltilen Açıklar](#-düzeltilen-açıklar)
  - [Açık Kalan Zafiyetler](#️-açık-kalan-zafiyetler)

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

### Threat Modelling (`/api/threatmodelling`)

> 🔍 Sistemdeki tehditleri STRIDE kategorisine göre listeleyen, okuma amaçlı endpoint'ler.

| Method | Endpoint | Auth | Açıklama |
|--------|----------|------|----------|
| `GET` | `/api/threatmodelling` | ❌ | Tüm tehditleri listeler |
| `GET` | `/api/threatmodelling/category/{category}` | ❌ | Belirtilen STRIDE kategorisindeki tehditleri listeler |
| `GET` | `/api/threatmodelling/open` | ❌ | Henüz kapatılmamış (Open) tehditleri listeler |
| `GET` | `/api/threatmodelling/summary` | ❌ | Kategori bazlı tehdit özetini döner (Open / Mitigated / AcceptedRisk) |

---

## Transaction State Machine

İşlem yaşam döngüsü `TransactionStateMachine` sınıfı aracılığıyla yönetilmektedir. Geçersiz durum geçişleri `InvalidOperationException` fırlatarak engellenir.

```
Pending ──► Authorized ──► Cleared ──► Settled
   │             │
   ▼             ▼
Declined      Reversed
   │             
   ▼             
Cancelled     
```

| Mevcut Durum | İzin Verilen Geçişler |
|---|---|
| `Pending` | `Authorized`, `Declined`, `Cancelled` |
| `Authorized` | `Cleared`, `Reversed`, `Cancelled` |
| `Cleared` | `Settled` |
| `Settled` | — (terminal) |
| `Declined` | — (terminal) |
| `Cancelled` | — (terminal) |
| `Reversed` | — (terminal) |

---

## Güvenlik Açıkları (Eğitim Amaçlı)

Bu projede kasıtlı olarak bırakılan başlıca açıklar ve mevcut düzeltme durumları:

### STRIDE Analizi

[STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats), Microsoft tarafından geliştirilen tehdit modelleme çerçevesidir. Aşağıdaki tablo projedeki tehditleri STRIDE kategorilerine göre sınıflandırmaktadır:

| Kategori | Tehdit | İlgili Endpoint / Bileşen | Durum |
|---|---|---|---|
| **S**poofing (Kimlik Sahteciliği) | `alg:none` ile imzasız JWT kabul ediliyor | Tüm korumalı endpoint'ler | ⚠️ Açık |
| **S**poofing | Hardcoded zayıf JWT secret — hashcat ile kırılabilir | `POST /api/auth/login` | ⚠️ Açık |
| **S**poofing | MD5 şifre hash'i — rainbow table ile kırılabilir | `POST /api/auth/login` | ⚠️ Açık |
| **T**ampering (Veri Manipülasyonu) | Negatif tutar ile bakiye artırma | `POST /api/transactions/authorize` | ✅ Düzeltildi |
| **T**ampering | Süresi dolmuş kart ile işlem yapma | `POST /api/transactions/authorize` | ✅ Düzeltildi |
| **T**ampering | SQL Injection ile veri manipülasyonu | `GET /api/transactions/search` | ⚠️ Açık |
| **T**ampering | Arbitrary SQL execution | `POST /_debug/execute-sql` | ⚠️ Açık |
| **T**ampering | Geçersiz durum geçişleri (ör. Settled → Pending) | `TransactionStateMachine` | ✅ Düzeltildi |
| **R**epudiation (İnkar) | Transaction ID tahmin edilebilir — kayıt inkâr edilebilir | `POST /api/transactions/authorize` | ✅ Düzeltildi |
| **R**epudiation | Şifre sıfırlama token'ı süresiz ve tekrar kullanılabilir | `POST /api/auth/reset-password` | ✅ Düzeltildi |
| **I**nformation Disclosure (Bilgi Sızdırma) | Full PAN yetkilendirme response'unda açıkta | `POST /api/transactions/authorize` | ✅ Düzeltildi |
| **I**nformation Disclosure | CVV response'da dönüyor | `POST /api/transactions/authorize` | ✅ Düzeltildi |
| **I**nformation Disclosure | Full PAN + CVV diğer endpoint'lerde açıkta | `GET /api/cards/{id}`, `GET /api/account/profile/{userId}` | ⚠️ Açık |
| **I**nformation Disclosure | Env vars, connection string açıkta | `GET /_debug/info` | ⚠️ Açık |
| **I**nformation Disclosure | OTP / reset token response'da dönüyor | `POST /api/auth/otp/send`, `POST /api/auth/forgot-password` | ⚠️ Açık |
| **I**nformation Disclosure | IDOR ile başka kullanıcının verisine erişim | `GET /api/cards/{id}`, `GET /api/account/profile/{userId}` | ⚠️ Açık |
| **D**enial of Service (Hizmet Engeli) | Pagination yok — tüm DB tek sorguda çekiliyor | `GET /api/transactions` | ⚠️ Açık |
| **D**enial of Service | Maksimum tutar sınırı yok | `POST /api/transactions/authorize` | ✅ Düzeltildi |
| **E**levation of Privilege (Yetki Yükseltme) | JWT role claim manipülasyonu (imza doğrulanmıyor) | Tüm korumalı endpoint'ler | ⚠️ Açık |
| **E**levation of Privilege | Admin SQL çalıştırma (auth yok) | `POST /_debug/execute-sql` | ⚠️ Açık |

---

### ✅ Düzeltilen Açıklar

| Açık | İlgili Kod | Düzeltme |
|------|-----------|----------|
| Negatif / sıfır tutar kabulü | `AuthorizationService.ProcessAsync` | `amount <= 0` kontrolü eklendi, geçersiz tutar reddediliyor |
| Maksimum tutar kontrolü yok | `AuthorizationService.ProcessAsync` | 100.000 TL üzeri işlemler engelleniyor |
| Kart vade tarihi kontrolü yok | `AuthorizationService.ProcessAsync` | Süresi dolmuş kartlar artık reddediliyor |
| Tahmin edilebilir transaction ID (`TXN000001`, `TXN000002`...) | `AuthorizationService.ProcessAsync` | UUID tabanlı rastgele ID ile değiştirildi (`TXN{8-char-guid}`) |
| Full PAN yetkilendirme response'unda (PCI DSS ihlali) | `AuthorizationService.ProcessAsync`, `AuthorizationResponse` | PAN maskelendi — yalnızca ilk 6 + son 4 karakter gösteriliyor (`123456*******7890`) |
| CVV yetkilendirme response'unda (PCI DSS ihlali) | `AuthorizationService.ProcessAsync`, `AuthorizationResponse` | CVV response'dan kaldırıldı |
| Geçersiz state geçişleri (ör. Settled → Pending) | `TransactionStateMachine` | İzin verilmeyen geçişler `InvalidOperationException` fırlatıyor |
| Şifre sıfırlama token'ı süresiz ve tekrar kullanılabilir | `PasswordResetToken`, migration `change_pwd_reset` | `ExpireAt` (token süresi) ve `IsUsed` (tek kullanımlık) alanları eklendi |

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
| Full PAN response'da (`CardController`, `AccountController`) | `GET /api/cards/{id}`, `GET /api/account/profile/{userId}` | 8.1 |
| MD5 ile şifre hashleme (PCI DSS ihlali) | `POST /api/auth/login` | - |
| Pagination eksikliği (DoS riski) | `GET /api/transactions` | - |
| CORS tamamen açık | Tüm endpoint'ler | - |
| Fraud detection / velocity check yok | `POST /api/transactions/authorize` | - |
