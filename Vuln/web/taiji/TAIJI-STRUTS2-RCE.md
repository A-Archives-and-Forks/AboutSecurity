---
id: TAIJI-STRUTS2-RCE
title: 深圳太极政府政务管理系统通用 Struts2 远程代码执行漏洞（wooyun-2012-09170）
product: taiji
vendor: 深圳太极软件有限公司（Shenzhen Taiji）
version_affected: "深圳太极政府政务管理系统（2012 年披露版本，Struts2 框架）"
severity: CRITICAL
tags: [rce, struts2, 反序列化, 国产, 政务, 远程代码执行]
fingerprint: ["深圳太极", "太极软件", "sztaiji", "struts2", "action.do", ".action"]
---

## 漏洞描述

深圳太极框架（Taiji）开发的政府政务管理系统存在通用 Struts2 漏洞（wooyun-2012-09170）。该系统采用 Struts2 框架，多个政府部门部署同一套系统，2012 年披露时可组合 Struts2 关键字利用实现远程代码执行（对应当时 Struts2 OGNL 注入类漏洞）。具体 S2- 编号未在报告中固定，评估时应结合部署版本确认对应 Struts2 漏洞。

**注意**：本条目只覆盖 wooyun-2012-09170（太极政务系统 Struts2 RCE）；Oracle 注入、政府服务中心越权等漏洞各自独立编号，不要合并。

## 影响版本

- 深圳太极政府政务管理系统（2012 年披露版本，Struts2 框架）

## 前置条件

- 目标为深圳太极政务管理系统且使用受影响的 Struts2 版本

## 利用步骤

1. 识别目标为深圳太极政府政务管理系统，确认 Struts2 框架特征（`.action` / `.do` 路径、Struts 响应头）
2. wooyun 原文（wooyun-2012-09170）披露的通用入口关键字：`inurl:common/common_info.action?wid=`（该 action 为受影响系统的通用入口）
3. 原文未固定具体 S2- 编号；确认目标部署的 Struts2 版本后，按对应年份公开的 Struts2 OGNL 注入漏洞（2012 年前后典型为 OGNL 表达式注入类）做验证
4. 严格授权：仅做无害 OGNL 探测（如计算表达式观察回显），不执行破坏性命令

## Payload

wooyun 原文未固定具体 S2- 编号、未披露完整 OGNL 请求。验证时先确认入口 `common/common_info.action?wid=`，再结合目标 Struts2 版本对应的公开 S2-xxx PoC 构造 OGNL 注入请求（不同版本 PoC 不同），此处不提供脱离版本的具体 Payload。

## 验证方法

1. 识别目标框架：以 `.action` / `.do` 结尾的 URL、`Struts` 响应特征
2. 在授权范围内核对 Struts2 版本对应的公开漏洞（OGNL 注入类）
3. 使用对应漏洞的验证请求确认（严格授权，避免破坏性 payload）

## 指纹确认

```bash
curl -s "http://target/" | grep -iE "太极|taiji|sztaiji"
# 探测 Struts2 特征路径
curl -s -o /dev/null -w "%{http_code}" "http://target/index.action"
```

## 修复建议

1. 升级 Struts2 组件至官方安全版本并移除 OGNL 静态访问
2. 联系厂商获取政务系统修复版本
3. 限制政务系统外网暴露面

## 参考

- wooyun-2012-09170: https://wooyun.laolisafe.com/bug_detail.php?wybug_id=wooyun-2012-09170
