# MapleKiosk-authority

### Example Payload
```
# admin access
{
  "sub": "shop_admin",        // 구분용 subject
  "shop_admin_id": 1,         // shop_admin 테이블 PK
  "shop_id": 1001,            // 가게 ID
  "email": "admin@shop.com",  // 관리자 이메일
  "role": "ADMIN",            // 권한
  "exp": 1620000000           // 만료 시간 (Unix Time)
}

# admin refresh
{
  "sub": "refresh_token",
  "shop_admin_id": 1,
  "type": "ADMIN",
  "exp": 1622592000
}

# kiosk access
{
  "sub": "kiosk",
  "kiosk_id": 2001,             // kiosk_device 테이블 PK
  "shop_id": 1001,              // 가게 ID
  "device_name": "Kiosk 1",     // 기기명
  "role": "KIOSK",              // 권한
  "exp": 1620000000
}

# kiosk refresh
{
  "sub": "refresh_token",
  "kiosk_id": 2001,
  "type": "KIOSK",
  "exp": 1622592000
}
```