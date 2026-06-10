# vip.t3go.cn API Endpoints (extracted 2026-06-08)
Source: `https://vip.t3go.cn/js/app.d03540df.js` (200KB bundle)
App name: "T3-admin" (enterprise vehicle management platform)
Total: 120 API paths found

## Auth Endpoints (prefix: /api/auth/)
```
/api/auth/getKey                    → AES key distribution (500 as of 2026-06-08)
/api/auth/oauth/password            → OAuth password grant (needs random from getKey)
/api/auth/oauth/mobile              → OAuth mobile grant (500)
/api/auth/sms/code                  → SMS verification code (500)
/api/auth/code/image/base           → Image captcha (500)
/api/auth/code/image/check          → Captcha verification
/api/auth/slider/image/get          → Slider captcha image (500)
/api/auth/slider/image/validate     → Slider captcha validation
/api/auth/forgetPwd/outlogin        → Password reset (500)
/api/auth/outlogin                  → External login
/api/auth/password/forget/submit    → Password forget submit
/api/auth/password/modify/submit    → Password change submit
/api/auth/queryResourceByAccountId  → Resource query by account (9999)
```

## Boss/Common Endpoints (prefix: /api/boss/common/)
```
/api/boss/common/city/list              → City list (9999 needs user)
/api/boss/common/city/listNew           → New city list
/api/boss/common/bank/list              → Bank list (9999 needs user)
/api/boss/common/getBusinessVehicle     → Business vehicle info (9999)
/api/boss/common/getCity                → Get city
/api/boss/common/getCityByCode          → Get city by code
/api/boss/common/getOpenCityByCityCode  → Open cities (9999)
/api/boss/common/getEmailImageCode      → Email image code
/api/boss/common/previewFile            → File preview (potential SSRF, 9999)
/api/boss/common/sceneList              → Scene list
```

## Enterprise Endpoints (prefix: /api/boss/enterprise/)
```
/api/boss/enterprise/getEnterpriseInfo        → Enterprise info (9999)
/api/boss/enterprise/get/org/config           → Org config
/api/boss/enterprise/org/config/update        → Update org config
/api/boss/enterprise/getOrgRulesByOrgId       → Org rules
/api/boss/enterprise/editOrgRuleShowName      → Edit rule name
/api/boss/enterprise/query/balance            → Balance query (9999)
/api/boss/enterprise/refund                   → Refund
/api/boss/enterprise/refundList               → Refund list
/api/boss/enterprise/findRefundAmount         → Refund amount
/api/boss/enterprise/getAccountSecondTypes    → Account types
/api/boss/enterprise/enablePersionPay         → Enable personal pay
/api/boss/enterprise/logout                   → Logout
/api/boss/enterprise/logoutApplyStatus        → Logout status
/api/boss/enterprise/logoutCheck              → Logout check
```

## Enterprise Registration (prefix: /api/boss/enterpriseRegistered/)
```
/api/boss/enterpriseRegistered/certification
/api/boss/enterpriseRegistered/getEnterpriseInfo
/api/boss/enterpriseRegistered/sign
```

## Third-Party Integration (prefix: /api/boss/company/third/v1/)
```
/api/boss/company/third/v1/getToken        → "三方认证失败:null"
/api/boss/company/third/v1/getThirdAppInfo → 500
/api/boss/company/third/v1/bind
/api/boss/company/third/v1/checkStatus
```

## Charter/Rental (prefix: /api/boss/company/charter/)
```
/api/boss/company/charter/calculate/moreCarPrice
/api/boss/company/charter/query/rentWrapRules
/api/boss/company/charter/query/rentWrapRulesDetail
/api/boss/company/charter/query/serviced/drivers
/api/boss/company/detailByUuid
```

## Fund Supervision (prefix: /api/boss/fund/supervise/)
```
/api/boss/fund/supervise/invalidCompanyAccount
/api/boss/fund/supervise/qryBankNo
/api/boss/fund/supervise/qryBusinessObsUrl
/api/boss/fund/supervise/qryEnterpriseDepository
/api/boss/fund/supervise/qrySubmitSupervisionReq
```

## Coupon / Color Custom / Address / Advertisement
```
/api/boss/coupon/query/companyCouponList
/api/boss/colorCustom/selectColorCustom
/api/boss/colorCustom/updateStyle
/api/boss/colorCustom/uploadPics
/api/addressBook/staff/getAuth
/api/boss/advertisement/rechargeActivity
```

## Gateway Routing
vip.t3go.cn itself returns 404 for /api/* (nginx catch-all).
All API calls go through gateway.t3go.cn/org-manager-boss/* prefix.
OAuth client: org-manager:HwEACu8r2jngK6OM (Basic auth header).

## Response Code Map
- 500 "系统异常" = service degraded
- 9999 "用户信息不存在" = client auth OK, needs user session
- 4100 "用户名或密码错误" = OAuth password, client OK, wrong credentials
- 4114 "client账号或密码错误" = wrong OAuth client
- 2017 "没有权限" = global auth filter (RPA domains)
