# Mlife.mo API端点枚举结果 (2026-06-08)

## 无需认证可访问的端点

### /view/* 系列 (GET请求)
| 端点 | 响应大小 | 数据类型 |
|------|---------|---------|
| /view/offers | 15,124B | 优惠数据(船票/餐饮/住宿) |
| /view/accommodations | 2,932B | 酒店房间(含电话邮箱) |
| /view/pointRedemptions | 2,057B | 积分兑换(150/300分) |
| /view/freeComps | 734B | 免费优惠(Valet Parking) |
| /view/onlineshopping | 1,584B | 在线购物(壹号广场等) |
| /view/guide | 334B | 用户指南(含mgm-static.itedigital.cn) |
| /view/news | 9,201B | RSS新闻 |
| /view/auto | 3,420B | RSS汽车新闻 |
| /view/digital | 8,212B | RSS数码新闻 |
| /view/education | (有数据) | RSS教育新闻 |
| /view/entertainment | (有数据) | RSS娱乐新闻 |
| /view/finance | (有数据) | RSS财经新闻 |
| /view/media | 5,896B | RSS媒体新闻 |
| /view/mobile | 8,884B | RSS手机新闻 |
| /view/reading | 4,788B | RSS阅读新闻 |
| /view/realestate | 9,152B | RSS房产新闻 |
| /view/sales | 9,535B | RSS销售新闻 |
| /view/sports | 7,373B | RSS体育新闻 |
| /view/technology | 7,619B | RSS科技新闻 |
| /view/travel | 9,240B | RSS旅游新闻 |

### 需要session的端点
| 端点 | 响应 |
|------|------|
| /view/baccaratTrend | SESSION_REQUIRED |
| /view/luckyDraw | SESSION_REQUIRED |

### 其他无认证端点
| 端点 | 方法 | 响应 |
|------|------|------|
| /encryptAES256 | POST | AES加密结果 |
| /GetPointsRedemptionTransactions | POST | {StatusCode:OK,TransDatas:[]} |
| /ESB_Token_Validator | POST | {StatusCode:Fail,CheckResult:Invalid} |
| /GetMlifeMobileModules | POST | false |
| /LoginMlifeESB | POST | {StatusCode:FAIL,StatusDescription:"Login failed..."} |
| /FourWindsIntegration/eHostWebservice/Barcode.asmx/GenerateCode | POST | 条形码图片 |

### 需要认证的端点(返回"登录时效已过")
/login, /user, /validatePIN, /RedeemPlayerOffer, /RedeemPointRedemptions,
/ESB_PayByPoints, /ESB_PostCharge_*, /GetPointsRedemptionTransactions(带参数),
/PayByPointsTriggerEmail, /ESB_GetRankingByPlayerId, /view/homeView, /view/transactions,
/view/messages, /view/promotions, /view/points, /view/user, /view/profile

## /view/accommodations 泄露的敏感信息
- Phone: (853) 88021888
- Email: hotelreservations@mgmmacau.com
- Links: https://www.mgm.mo/s/mobile/grand-room/ 等6种房型

## /view/offers 数据结构
```json
{
  "Id": "30677",
  "Name": "喷射飞航普通位船票",
  "Description": "当天积满30分，即可换领...",
  "ImageUrl": "/config/images/Content/SpecialOffers/mobile/30677_3.jpg",
  "Type": "Comp|124|Daily Offer Promotion...",
  "RedeemMethod": "TurboJET - Economy",
  "MaxRedeem": "9999999",
  "Sequence": "68"
}
```

## ASMX服务枚举
| 服务 | 状态 |
|------|------|
| Barcode.asmx | WSDL完全暴露，GenerateCode可调用 |
| PlayerService.asmx | 存在→customerror.aspx |
| LoyaltyService.asmx | 存在→customerror.aspx |
| AuthService.asmx | 存在→customerror.aspx |
| PaymentService.asmx | 存在→customerror.aspx |
| ReservationService.asmx | 存在→customerror.aspx |
| IntegrationService.asmx | 存在→customerror.aspx |
| ESBService.asmx | 存在→customerror.aspx |

## ADFS端点枚举
| 端点 | 状态码 |
|------|--------|
| /adfs/ls/idpinitiatedsignon.aspx | 200 |
| /adfs/ls/idpinitiatedsignoff.aspx | 200 |
| /adfs/services/trust/2005/usernamemixed | 400 |
| /adfs/services/trust/2005/windowstransport | 401 |
| /adfs/services/trust/13/usernamemixed | 400 |
| /adfs/services/trust/13/windowstransport | 503 |
| /adfs/services/trust/mex | 200 |
| /adfs/ls/ | 200 |
| /adfs/oauth2/authorize | 200 |
| /adfs/oauth2/token | 200 |
| /adfs/.well-known/openid-configuration | 200 |
| /adfs/discovery/keys | 200 |
| /FederationMetadata/2007-06/FederationMetadata.xml | 200 |
