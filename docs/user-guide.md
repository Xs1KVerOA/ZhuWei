# 烛微 ZhuWei：使用文档

## 1. 登录

服务启动后，控制台会输出类似内容：

```text
[烛微] login: http://127.0.0.1:8010/login
[烛微] random token: <本次启动随机 token>
```

推荐从项目根目录运行：

```bash
./start.sh
```

打开登录页，输入本次启动输出的随机 token。登录成功后浏览器会写入 HttpOnly session cookie。

注意：当前产品每次启动都会生成新 token，服务重启后旧会话会失效，需要用新 token 重新登录。

## 2. 数据看板

数据看板展示当前入库规模和运营状态，包括漏洞总数、告警数量、产品库数量、分析状态分布、漏洞等级分布等。看板适合用于快速确认系统是否正常采集、是否存在积压分析、是否有待处理告警。

## 3. DeepSeek 配置

进入 DeepSeek 区域后可以：

- 查看当前 API Key 来源：环境变量、本地数据库或未配置。
- 保存 DeepSeek API Key。
- 清除数据库中的 API Key。
- 手动刷新余额。

保存的 API Key 会写入本地 SQLite 的 `app_settings` 表，前端只展示脱敏后的 Key。

## 4. 站点会话

AVD、CNVD 等站点可能需要真实浏览器会话。站点会话区提供：

- 刷新 AVD Cookie。
- 刷新 CNVD Cookie。
- 手动保存 CNVD Cookie。
- 清除已保存 Cookie。
- 刷新后立即运行对应数据源。

如果页面提示验证码、WAF 或登录态失效，需要使用本机浏览器完成验证后再刷新会话。

## 5. 关注产品

关注产品是自动分析的核心入口。可以通过两种方式关注：

- 在产品库搜索产品，点击关注。
- 在漏洞条目中点击关注对应产品。

后续新漏洞命中关注产品，且等级满足 high/critical 条件时，系统会自动进入分析队列。

## 6. 产品库

产品库来自 BIU 产品目录，支持搜索和分页浏览。采集时采用页级流式入库，每采集一页立即写入数据库，因此即使后续页面遇到限流，已采集产品也不会丢失。

常见操作：

- 搜索软件、厂商或组件。
- 展开清单查看更多产品。
- 将高价值产品加入关注列表。
- 点击“对齐漏洞”，将当前漏洞库中的漏洞与产品库做一次本地直接匹配；如果存在新告警且本地无法确认产品，会调度 DeepSeek Flash 做产品归属识别。
- 产品卡片会展示产品库统计的漏洞数量、本地命中数量，以及最新 3 条关联漏洞。

说明：

- 产品名、打开按钮和最新漏洞名称均为普通超链接，点击后按浏览器默认行为打开对应外部页面。
- DeepSeek Flash 产品归属只用于判断漏洞对应的产品，不会搜索 POC、EXP 或利用载荷。
- 手动接口为 `POST /api/products/align-vulnerabilities`。

## 7. 漏洞分析

漏洞分析区分为三列：

- 排队中。
- 正在分析。
- 已分析。

手动分析：

1. 在漏洞情报或告警列表中找到目标漏洞。
2. 点击分析按钮。
3. 任务进入队列后等待 Claude Code 执行。
4. 完成后在已分析区域查看报告、POC、EXP 和异常信息。

删除分析：

- “删除分析”只清理该漏洞的分析报告、过程事件和生成的 POC/EXP，不会删除漏洞本身。
- 排队中或正在运行的任务不能直接删除，需要先取消或等待结束。

失败处理：

- `GET /api/analysis/failure-stats` 查看失败分类。
- `POST /api/analysis/requeue-failed` 一键重跑所有失败分析。
- `POST /api/vulnerabilities/{id}/analysis/cancel` 取消排队中或运行中的分析。

## 8. 告警规则

告警规则用于把入库漏洞筛选为真正需要处理的告警。

字段说明：

- 最低等级：低于该等级的漏洞只入库不告警。
- CVE 去重：同一 CVE 多源命中时只生成一条告警。
- 跳过关键词：忽略白名单限制，除黑名单外全部按等级进入告警。
- 告警窗口：只保留指定天数内的新增漏洞进入告警判断。
- 白名单关键词：配置后必须命中才告警。
- 黑名单关键词：命中后不告警，优先级高于白名单。

## 9. 告警中心

告警中心支持：

- 待处理、已确认、全部状态切换。
- 按 CVE、标题、产品搜索。
- 按来源过滤。
- 查看 POC/EXP、分析报告和异常详情。
- 确认告警。

建议日常工作流：

1. 先看待处理告警。
2. 优先处理 critical/high 且有 POC/EXP 的条目。
3. 对命中关注产品的漏洞执行或查看分析。
4. 处理完成后确认告警。

## 10. 数据源

数据源列表展示每个源的：

- 名称。
- 类别。
- 调度计划。
- 最近状态。
- 最近入库数量。
- 最近运行时间。

可以手动运行单个源，也可以通过顶部按钮运行 regular 或 slow 源组。

GitHub Security Advisories、GitHub Security Lab 和 GobyVuls 会作为 regular 源入库，但默认不产生高危告警。Sploitus 与 CXSecurity 已接入为可选 POC/EXP RSS 线索源，默认关闭，可在网络可达环境手动启用。带 CVE/GHSA 的漏洞会在后台按预算自动搜索 GitHub 仓库和代码证据，并将命中的 POC/EXP 写入分析中心的 POC/EXP Tab。

相关接口：

```bash
curl -H "X-App-Token: <token>" http://127.0.0.1:8010/api/sources
curl -X POST -H "X-App-Token: <token>" http://127.0.0.1:8010/api/jobs/regular/run
curl -X POST -H "X-App-Token: <token>" http://127.0.0.1:8010/api/sources/cisa_kev/run
curl -X POST -H "X-App-Token: <token>" http://127.0.0.1:8010/api/sources/github_advisories/run
```

## 11. 漏洞情报

漏洞情报区是完整入库列表，不只包含告警。支持：

- 按 CVE、标题、产品搜索。
- 按等级筛选。
- 查看漏洞来源、描述、链接、POC/EXP、CVSS。
- 查看 GitHub 证据标签、可信度评分和 POC/EXP Tab 中的 GitHub 命中。
- 手动触发分析。
- 关注产品。

## 12. 报表与评分接口

日报：

```bash
curl -H "X-App-Token: <token>" http://127.0.0.1:8010/api/report/daily
```

周报：

```bash
curl -H "X-App-Token: <token>" http://127.0.0.1:8010/api/report/weekly
```

源健康：

```bash
curl -H "X-App-Token: <token>" http://127.0.0.1:8010/api/sources/health
```

评分告警：

```bash
curl -H "X-App-Token: <token>" "http://127.0.0.1:8010/api/alerts/scored?status=new&limit=20"
```

单条威胁评分：

```bash
curl -H "X-App-Token: <token>" http://127.0.0.1:8010/api/vulnerabilities/1670/threat-score
```

产品与漏洞对齐：

```bash
curl -X POST \
  -H "X-App-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"only_unlinked": true, "deepseek_flash": true, "ai_limit": 5}' \
  http://127.0.0.1:8010/api/products/align-vulnerabilities
```

## 13. 常见问题

### 页面还在 `/app`，但接口报 401

服务重启后随机 token 改变，旧 session cookie 会失效。打开 `/login`，使用控制台输出的新 token 重新登录。

### 某些源持续失败

进入源健康中心查看错误类型。如果是验证码、WAF、登录态失效，需要刷新站点会话或更新 Cookie。如果是 429，降低采集频率或等待限流恢复。

### 分析长时间没有结果

检查：

- DeepSeek API Key 是否配置。
- Claude Code 是否可用。
- `/api/claude-code/status` 是否显示 available。
- 分析并发是否过高。
- 失败分类是否集中在超时、鉴权或网络错误。
