---
id: TAIJI-ELECTRONIC-GOV-ORACLE-SQLI
title: 深圳太极电子政务/电子监察系统通用型 Oracle 注入漏洞（wooyun-2014-072715）
product: taiji
vendor: 深圳太极软件有限公司（Shenzhen Taiji）
version_affected: "深圳太极电子政务系统/电子监察系统（wooyun-2014-072715 披露版本）"
severity: HIGH
tags: [sqli, oracle, 注入, 国产, 政务, 电子政务]
fingerprint: ["深圳太极", "太极软件", "sztaiji", "电子政务", "电子监察"]
---

## 漏洞描述

深圳太极软件有限公司的电子政务系统、电子监察系统存在多处通用型 Oracle 注入漏洞（wooyun-2014-072715）。漏洞位于 `menu` 与 `design` 参数，多个部署同一套系统的政府部门均受影响，属于通用型漏洞而非单点案例。该漏洞可被用于读取数据库敏感信息。

**注意**：本条目只覆盖 wooyun-2014-072715（电子政务/监察系统 Oracle 注入）；太极其他产品线（政府服务中心、Struts2 漏洞）各自独立编号，不要合并。

## 影响版本

- 深圳太极电子政务系统、电子监察系统（wooyun-2014-072715 披露时通用受影响）

## 前置条件

- 目标为深圳太极电子政务/电子监察系统

## 验证方法

```bash
# 仅限授权测试：对 menu / design 参数做 Oracle 报错/布尔/时间盲注探测
curl -s "http://target/<接口路径>?menu=1'"
curl -s "http://target/<接口路径>?design=1'"
# 观察是否存在 Oracle 数据库报错或响应差异
```

## 指纹确认

```bash
curl -s "http://target/" | grep -iE "太极|taiji|sztaiji|电子政务|电子监察"
```

## 修复建议

1. 联系厂商获取修复版本
2. 对 menu/design 等参数使用参数化查询
3. 限制政务系统外网暴露面

## 参考

- wooyun-2014-072715: https://wooyun.laolisafe.com/bug_detail.php?wybug_id=wooyun-2014-072715
