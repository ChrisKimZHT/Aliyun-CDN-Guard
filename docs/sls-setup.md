# CDN 实时日志投递精简配置

本程序不创建 Project、Logstore 或实时日志投递。首次部署前在阿里云控制台完成：

1. 打开日志服务 SLS，创建 Project 和**标准型 Logstore**；区域建议与 CDN 主要业务区域及运行实例一致。
2. 打开 CDN 控制台的“日志管理 → 实时日志”，创建投递项目并选择上述 Project/Logstore。
3. 将 `cdn.domains` 中的域名加入投递。确认原始日志至少包含 `domain`、`client_ip`、`uri`、`uri_param`、`user_agent` 和 `uuid`。
4. 将 endpoint、region、Project 和 Logstore 写入 `config.yml` 的 `sls` 段。
5. 给运行实例的 RAM 角色附加最小权限策略。复制 `docs/ram-policy.example.json`，替换尖括号占位符和域名。若首次调用 CDN 配置 API 提示服务关联角色权限不足，由管理员预先创建服务关联角色；不要长期授予本程序 `ram:CreateServiceLinkedRole`。

目标 CDN 域名不能同时启用 CDN 的 IP 白名单功能；阿里云的 `ip_allow_list_set` 与本程序使用的 `ip_black_list_set` 互斥。程序自身的业务白名单只影响检测流程，不会创建 CDN IP 白名单。

消费组不需要在控制台创建。程序第一次启动时自动创建，`cursor_position` 仅在消费组首次建立时生效：生产环境建议先设为 `end`，避免用历史流量触发封禁。

上线顺序：先保持 `cdn.dry_run: true` 观察日志和阈值；确认无误后改为 `false`。SLS 实时投递本身通常存在分钟级延迟，因此这不是毫秒级防护。

官方参考：

- [投递 CDN 实时日志到 SLS](https://help.aliyun.com/zh/sls/deliver-cdn-real-time-logs-to-sls-to-analyze-user-access)
- [CDN 实时日志字段](https://help.aliyun.com/zh/sls/log-fields-22)
- [使用消费组消费日志](https://help.aliyun.com/en/sls/developer-reference/use-consumer-groups-to-consume-data)
- [CDN IP 黑名单参数](https://help.aliyun.com/zh/cdn/developer-reference/parameters-for-configuring-features-for-domain-names)
