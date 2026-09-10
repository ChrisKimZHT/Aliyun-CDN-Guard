# Aliyun CDN Guard

从阿里云 SLS 持续消费 CDN 实时访问日志，按 `client_ip` 及可选的 UA、URI 联合维度统计请求频率，超过 `N 次 / M 秒` 后将来源 IP 写入触发域名的 CDN IP 黑名单，并在惩罚期结束后自动移除。

## 行为说明

- IP 始终是聚合维度；开启 UA/URI 后，聚合键分别变为 `IP+UA`、`IP+URI` 或 `IP+UA+URI`。
- `match_regex` 是 Python 正则筛选器：设置后，仅匹配的请求参与该维度统计；实际聚合仍使用完整 UA 或规范化 URI。
- URI 参数可保留、全部忽略，或按参数名忽略。白名单 URI 正则匹配规范化后的 URI。
- 域名、IP/CIDR、UA 正则、URI 正则任一白名单命中后，不记录事件，也不参与检测。
- 每个域名单独封禁；封禁时长为 `base * multiplier^(次数-1)`，不超过 `max`。
- 不设置 CDN 自定义响应码，沿用该配置的现有/默认行为。
- `cdn.ip_acl_xfwd` 默认是 `on`，与 SLS `client_ip` 的来源一致；同步 IP 列表时会同时确保此匹配模式。
- 同步前读取远端黑名单。已存在的条目视为外部维护；到期时只删除本程序实际添加的条目。
- SQLite 记录事件、惩罚次数及条目归属；SLS `uuid` 用于幂等去重。

阈值窗口及封禁时长统一使用秒；例如 `window_seconds: 300` 表示 5 分钟。配置中的正则表达式来自可信管理员，并直接使用 Python `re` 语法。

## 本地安装

```bash
conda env create -f environment.yml
conda activate aliyun-cdn-guard
cp config.example.yml config.yml
cp .env.example .env
aliyun-cdn-guard --config config.yml --check-config
aliyun-cdn-guard --config config.yml
```

也可以在已创建的环境中安装：

```bash
conda activate aliyun-cdn-guard
pip install -e '.[test]'
pytest
```

生产环境优先使用 ECS RAM 角色。SDK 使用阿里云默认凭证链；本地调试可将 `ALIBABA_CLOUD_ACCESS_KEY_ID`、`ALIBABA_CLOUD_ACCESS_KEY_SECRET` 和可选 STS token 放入 `.env`。`.env` 已被 Git 忽略，仍不应放置主账号 AccessKey。

SLS 与最小 RAM 权限配置见 [docs/sls-setup.md](docs/sls-setup.md)，完整配置项见 [config.example.yml](config.example.yml)。

## Docker

```bash
docker build -t aliyun-cdn-guard:0.1.0 .
docker run -d --name aliyun-cdn-guard --restart unless-stopped \
  -v "$PWD/config.yml:/app/config.yml:ro" \
  -v "$PWD/data:/app/data" \
  aliyun-cdn-guard:0.1.0
```

在 ECS 上运行容器时，容器默认可通过实例元数据服务取得 RAM 角色临时凭证。若实例限制容器访问元数据服务，请按 ECS 网络策略显式放行 IMDS；不要将长期 AccessKey 烘焙进镜像。

## 安全上线检查

1. 只在 `cdn.domains` 列出确需管理的域名。
2. 完成业务出口、监控、搜索引擎等 IP/UA/URI 白名单。
3. 保持 `dry_run: true` 运行至少一个业务高峰，观察阈值日志。
4. 备份 `data/guard.db` 所在持久卷后再启用真实同步。
5. CDN IPv4/IPv6 黑名单分别存在数量上限；达到上限时程序拒绝覆盖并记录错误，以避免截断远端配置。

当前版本为单实例设计。不要让多个容器共享同一个 SQLite 文件；高可用部署需改用支持并发协调的状态存储。
