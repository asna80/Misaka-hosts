# hosts-aggregator

从 **geosite 域名库**取域名清单，用**香港/日本 DoH 现解析 + 证书探测**生成一份可用的 hosts 文件，每天自动重建。你只需要订阅一条 URL。

## 数据源：geosite，不是 hosts 仓库

域名清单来自 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)，和你在 mosdns 里用的是同一套 `geosite` 数据：

```sh
python aggregate.py --geosite "geolocation-!cn,steam,epicgames,gog,github,category-games"
```

- `geolocation-!cn` 就是"没有中国大陆接入点"的完整海外域名集（内部 `include:` 会递归展开）；
- `steam` / `epicgames` / `gog` / `github` / `category-games` 补上游戏与 GitHub 的精细分类；
- **`@cn` 标记的条目全部丢弃**（Steam 国内 CDN 那些，如 `8686c.com`、`steamcontent.com` 的阿里云节点）——按你的要求，本来也连不上；
- `regexp:` / `keyword:` 无法枚举成 hostname，跳过并计数。

这样域名清单是"结构化、有分类、有人维护"的，而不是 2 万条混杂的加速表。

## 它解决的到底是什么问题

同一个域名，先解析出一堆候选 IP，然后**只写那个真的能连的**：

| 记录类型 | 判断方式 |
|---|---|
| IPv4 | 对每个候选 IP 做 `TCP:443 + SNI + 证书校验`，通过的才算数，多个通过取最快的 |
| IPv6 | CI 环境没有 IPv6 出口，无法直连验证 → 用 DoH 交叉验证：只保留「当前解析器仍然返回这个 AAAA」的记录 |
| 全部失败 | 沿用上一版的值，但**先确认上一版那个 IP 今天 TCP 还连得上**；连续 7 轮不通才丢弃 |

### IPv6 这一层为什么不直接信国内 DNS

这是实测出来的坑，不是理论担心：

```
www.google.com      AAAA → 2001::1                        # Teredo，GFW 伪造应答
000webhost.com      AAAA → 2a03:2880:f10e:83:face:b00c:0:25de   # Facebook 网段，同样是伪造
```

GFW 对 AAAA 查询同样会注入伪造应答，所以国内解析器（AliDNS）给出的 IPv6 **不能作为新记录的来源**（国内解析器已从默认配置里移除）。代码里的规则是：

| 情况 | 处理 |
|---|---|
| 香港/日本/海外解析器返回这个 AAAA | `doh-refreshed` / `verified`，采信 |
| 只有国内解析器返回 | 丢弃（无法排除伪造） |
| 命中 `2001::/32`、`2002::/16`，或非 Facebook 域名命中 `2a03:2880::/32` | 一律当伪造丢弃 |

另外每个域名最终只写 **1 个 IPv4 + 1 个 IPv6**。这是故意的：同族写多条，客户端通常只连第一条，坏 IP 会直接变成超时，比只写一条对的更糟。

## 产物

| 文件 | 说明 |
|---|---|
| `dist/hosts.txt` | 最终 hosts，**你的订阅地址就是这个** |
| `dist/selected.csv` | 审计表：每个域名选了什么 IP、来自哪个源、握手耗时、状态 |
| `dist/stats.json` | 本轮统计（各源贡献、各状态计数、耗时），Actions 摘要里也会打印 |
| `dist/prev.json` | 内部状态快照，用于「沿用上一版」和失败计数，别手改 |

`selected.csv` 里的状态含义：

| 状态 | 含义 |
|---|---|
| `verified` | TLS 握手成功且证书匹配该域名 —— 最可信 |
| `tier1-grace` | 只来自精选源，TCP 能通但 TLS 没完成（CDN 边缘/地区限制常见），首次引导时保留 |
| `carried` | 本轮没探测成功，沿用上一版且该 IP 仍可连 |
| `doh-refreshed` | 上游的 IPv6 已过期，用当前 DoH 返回的 AAAA 替换 |
| `cert-mismatch` | 证书与域名不匹配，**一律不写入**（多半是过期或错误 IP） |
| 空 | 该域名只有 IPv6 或只有 IPv4 |

## 部署（不需要本地装 git）

1. 新建一个 **public** 仓库（比如 `hosts`）。public 仓库的 Actions 免费。
2. 把这两个文件按原路径放上去：
   ```
   aggregate.py
   .github/workflows/build.yml
   ```
   `sources.txt` 只有回退到「上游 hosts 源」模式时才需要，用 geosite 不用传。
3. 仓库 **Settings → Actions → General → Workflow permissions** 选 **Read and write permissions**（否则 Action 无法提交结果）。
4. **Actions → build-hosts → Run workflow** 手动跑一次，参数留空即用默认：
   域名 = `geolocation-!cn,steam,epicgames,gog,github,category-games`，
   解析器 = `hk-hkg.doh.sb` + `jp-kix.doh.sb`（失败自动退 Cloudflare / Google）。
5. 跑完后 `dist/hosts.txt` 就有了。

## 订阅地址

```
https://raw.githubusercontent.com/<你的用户名>/<仓库名>/main/dist/hosts.txt
```

国内直连 raw 经常不通，备选（把整条 URL 拼在后面）：

```
https://ghproxy.net/https://raw.githubusercontent.com/<用户名>/<仓库>/main/dist/hosts.txt
https://gh-proxy.com/https://raw.githubusercontent.com/<用户名>/<仓库>/main/dist/hosts.txt
https://cdn.jsdelivr.net/gh/<用户名>/<仓库>@main/dist/hosts.txt      # 有 CDN 缓存延迟，不建议当主源
```

## OpenWrt 接入

### 方案 A：hostupdater 自定义源（最省事）

在 hostupdater 的「自定义源 / 其他 hosts 源」里填上面那条 URL，定时设成每天一次（建议 04:40 以后，留出 Action 跑完的余量）。

### 方案 B：dnsmasq addnhosts（推荐，不碰 /etc/hosts）

hostupdater 是往 `/etc/hosts` 里写，和系统自带条目混在一起，出问题不好回滚。更干净的做法是单独挂一个文件：

```sh
# /usr/bin/update-game-hosts.sh
#!/bin/sh
set -e
URL="https://raw.githubusercontent.com/<用户名>/<仓库>/main/dist/hosts.txt"
TMP=/tmp/hosts.new
OUT=/etc/hosts.d/game.hosts
mkdir -p /etc/hosts.d
curl -fsSL --retry 3 --max-time 60 "$URL" -o "$TMP" || exit 1
# 基本校验：非空、行数 >500、没有 HTML
[ -s "$TMP" ] || exit 1
[ "$(wc -l < "$TMP")" -gt 500 ] || exit 1
grep -qi '<html' "$TMP" && exit 1
cp -f "$OUT" "$OUT.bak" 2>/dev/null || true
mv -f "$TMP" "$OUT"
/etc/init.d/dnsmasq reload
```

```sh
chmod +x /usr/bin/update-game-hosts.sh
echo "40 4 * * * /usr/bin/update-game-hosts.sh" >> /etc/crontabs/root
/etc/init.d/cron restart
```

再让 dnsmasq 认这个文件（`/etc/config/dhcp` 里已经有 `addnhosts` 就追加路径）：

```sh
uci add_list dhcp.@dnsmasq[0].addnhosts='/etc/hosts.d/game.hosts'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

验证：

```sh
nslookup store.steampowered.com 127.0.0.1
nslookup www.gog.com 127.0.0.1        # 应同时看到 A 和 AAAA
logread | tail -20                     # 看 dnsmasq 有没有报错
```

## 手动补充：覆盖不到的地方自己加

geosite 是后缀语义、hosts 只能精确匹配，覆盖缺口一定会有。留了两个手动通道，**放进仓库就自动生效，不用改代码、不用改 workflow**：

| 文件 | 格式 | 作用 |
|---|---|---|
| `manual-domains.txt` | 每行一个域名 | 无条件并入域名清单，走 DoH 解析 + 证书探测 |
| `manual-hosts.txt` | 每行 `IP 域名` | 把 IP 钉成**最高优先级候选**，但仍要过证书校验；不过就退回 DoH |

```text
# manual-domains.txt
dl.example.com
api.example.net
```

```text
# manual-hosts.txt
23.45.136.230  steamcommunity.com
2a04:4e42::497 www.gog.com
```

`manual-hosts.txt` 里的 IP 若证书校验失败，**不会被写进去**，而是自动回退到 DoH 现解析——手动填错不会污染结果。

## 子域枚举：什么时候需要，怎么跑

geosite 的 `domain:x.com` 覆盖所有子域，但 hosts 写不出子域，所以像 `store.steampowered.com` 这种必须显式列。默认清单里已经硬编码了 53 个关键主机名（`CRITICAL_HOSTS`）。还有缺口时，用 `enum_subs.py` 从证书透明日志里挖：

```sh
python enum_subs.py --seeds seeds-platforms.txt --out subdomains.txt --cache .crtcache --workers 3
```

- `seeds-platforms.txt` 是 12 个平台（GitHub/Epic/Steam/Ubisoft/GOG/Docker/NVIDIA/AMD/Intel/Apple/Microsoft/OneDrive）的种子域名
- **可断点续跑**：每查完一个种子就落盘，中断后重跑会跳过已完成的
- 实测 crt.sh 单域名 20–110 秒，全部种子约 1–2 小时
- 生成的 `subdomains.txt` 放进仓库，Action 会自动并入（内部走 `--domain-list`）

注意：

- 不要往种子里加 `github.io`、`azureedge.net`、`trafficmanager.net` 这类**公共后缀**——证书日志里有上百万条，会把枚举跑爆；
- crt.sh 返回的通配符（`*.x.com`）会被丢弃，hosts 用不了。

## 保底策略做了什么（以及它的底线）

记录不是「验证通过 / 丢弃」两档，中间有几层递减的保底。每一层的判据和风险如下：

| 状态 | 触发条件 | 写入的 IP | 能保证什么 | 残余风险 |
|---|---|---|---|---|
| `verified` | TLS 握手 + 证书匹配域名 | 探活最快的候选 | 站点身份正确 | 几乎没有 |
| `tier1-grace` | **精选源**给出 + TCP:443 通 + 证书校验不是「不匹配」 | 该源 IP | IP 活着、端口开着、不是错误证书 | 可能活着但已不是该域名的最新边缘 → 访问慢或失败 |
| `doh-resolved` | 上游 IP 全部验证失败 | 海外 DoH **现解析**的 A 记录 | 就是「此刻正确」的地址 | 这是**解析器视角**的 IP，Akamai/CloudFront 类会偏向美国边缘 |
| `carried` | 上一版 IP + 今天 TCP 仍通 | 上一版 IP | 至少没死 | 可能已不再服务该域名 |
| `critical-grace` | 仅关键域名 + 有 TCP 通的源候选 | 该候选 | IP 活着 | 同 `tier1-grace` |
| **不做** | 所有候选 TCP 都不通，且 DoH 也拿不到 | **不写这条** | 绝不让域名指向死 IP | 该域名若同时被污染，会退回被污染的 DNS |

**核心不变量**：任何写进 `dist/hosts.txt` 的 IPv4，至少满足下面一条——

1. TLS + 证书验证通过；或
2. TCP:443 可连（排除死 IP）；或
3. 是海外 DoH 当前的权威答案。

不存在「完全没有任何证据」的记录。这也是为什么早期版本里 `critical-fallback`（不看可达性直接取源 IP）被我改掉了：它会把域名解析到一个连不上的地址，比不写更糟。

想更严格就加 `--strict`：只信 `verified`（`carried` 保留，因为它是曾经验证过的值）。

## 就近解析：为什么要用「近端 DoH」，以及国内 DoH 不可信

CDN 的边缘是按**解析器出口位置**分发的，不是按你的位置。所以：

| 用谁解析 | 拿到的边缘 | 适合 |
|---|---|---|
| Cloudflare / Google DoH（跑在 GitHub Actions） | 美国边缘 | 被墙站点（拿到真实地址即可） |
| **香港 / 日本 DoH（默认：`hk-hkg.doh.sb`、`jp-kix.doh.sb`）** | 香港 / 日本边缘 | **默认方案：既真实又就近** |
| ~~AliDNS / DNSPod（国内）~~ | 国内边缘，但被墙域名返回污染地址 | **已移除，见下方实测** |

国内 DoH 的实测结果（同一时刻连续查询）：

| 域名 | AliDNS | DNSPod | 真值参考 |
|---|---|---|---|
| www.google.com | 185.45.5.35 / 157.240.7.20 | 157.240.7.20 | 142.251.x |
| www.youtube.com | 104.244.42.197（Twitter 段） | 157.240.7.20（Facebook 段） | 142.251.x |
| steamcommunity.com | 174.36.228.136 | 45.114.11.238 | 23.x（Akamai） |

**结论：国内 DoH 对被墙域名系统性返回伪造地址，而且污染 IP 每次轮换**，所以固定黑名单没用，**国内解析器已从默认配置中移除**。唯一可靠判据是**证书复核**：这些伪造 IP 拿不出目标域名的合法证书，会在 TLS 阶段被淘汰。

因此这里的策略是「多解析器取候选池 + 证书投票」，而不是采信某一个解析器的答案：

```
候选池 = 上游 IP + 香港/日本 DoH 答案 + 海外 DoH 答案
        ↓
逐个 TCP:443 + SNI + 证书校验
        ↓
通过者胜出（优先近端来源，其次上游，最后海外）
```

默认就用你给的两个节点，不用传参：

```sh
python aggregate.py --out dist        # 内置 hk-hkg + jp-kix
```

要换节点（含自建 `doh-server` / `dnscrypt-server`）：

```sh
python aggregate.py --doh-near "https://hk-hkg.doh.sb/dns-query,https://jp-kix.doh.sb/dns-query" --out dist
```

支持标准 DoH（RFC 8484，GET 与 POST 都试），所以只收标准格式的服务也能用。

**先体检，再构建**：

```sh
python aggregate.py --doctor
```

它会打印每个解析器的可达性、延迟、是否在返回污染地址（判据：同一个 IP 覆盖多个无关域名），以及 `store.steampowered.com` 拿到的是 `23.15.x`（亚太）还是 `23.192.x`（美国）。Workflow 里已经把这一步做成独立步骤，每次跑都会留在日志里。

两个保命机制：

- **端点熔断**：某个 DoH 连续失败 8 次后整轮跳过。否则一个不可达的端点 × 1.7 万个域名会直接把 Action 拖到超时。
- **DoH 全挂时**：IPv6 退回上游值并标记 `upstream-unverified`，不会因为解析器不可用就丢掉所有 IPv6。

## 为什么不直接把所有域名交给 DoH 解析

能，但要接受一个代价：**DoH 返回的是「解析器视角的最优」，不是「你路由器视角的最优」**。

- GitHub 这类固定段（`140.82.x`）全球一致，DoH 拿到什么都能用；
- Steam / Epic / GOG 走 Akamai、CloudFront 的单播边缘，Cloudflare DoH 从北美解析会返回**美国边缘**。国内直连这些边缘往往比亚太边缘慢几倍甚至不可达——这正是国内 hosts 项目存在的意义；
- 反过来，上游的 IP 经常过期。**过期的 IP 一定没用**，DoH 至少给「此刻正确」的地址。

所以默认策略是分层的：**上游当「域名清单」+「国内调优先验」，能验证就用它的 IP，验证不过才用 DoH 现解析补位**（`doh-resolved`）。

如果你想验证「全靠 DoH」是什么效果，直接跑：

```sh
python aggregate.py --ignore-upstream-ip --out dist
```

它会忽略上游所有 IPv4，只保留域名清单，IPv4 全部现解析。跑完对比 `stats.json` 里 `verified` 与 `doh-resolved` 的比例，以及 `hosts.txt` 里 Steam/Epic 的 IP 段是不是变成了美国边缘——你就能自己判断哪种更适合你的线路。

## 调参

- **文件太大**：`sources.txt` 里把 `2|zyxyz|...` 这行删掉（或注释掉），域名数会从 2.3 万降到几百，文件从 ~1.3MB 降到几十 KB，对路由器更友好。
- **探测更狠一点**：`--max-probe 10 --max-seconds 3000`（Action 输入框里也能填）。
- **第一次跑发现丢得太多**：先看下面的「跑完先看这三个数」，别急着放宽判定。

## 跑完先看这三个数

`dist/stats.json` 里的 `v4_detail` 直接告诉你「丢掉的是坏 IP，还是探针自己的问题」：

| 字段 | 含义 | 偏高说明 | 该怎么办 |
|---|---|---|---|
| `verified` | TLS+证书都通过的 | 越多越好 | — |
| `drop_ip_unreachable` | TCP 都连不上 | 上游表老化，IP 真死了 | 正常，这正是要过滤的 |
| `drop_tcp_open_no_tls` | TCP 通、TLS 完不成 | **探针侧网络问题**（出口被拦/并发太高） | `--timeout` 提到 4、`--concurrency` 降到 128 |
| `drop_cert_mismatch` | TLS 通但证书不对 | 上游 IP 已过期，或不是这个站 | 正常 |
| `critical-fallback` | 刚需域名探活全失败、兜底保留 | 一般很小 | 看 `selected.csv` 里是哪几条 |

`v6_detail` 里：`matched_upstream` 是上游记录被现网 DNS 确认，`refreshed_by_trusted_doh` 是海外 DoH 补的新记录，`unconfirmed_cn_only` 是「只有国内解析器支持、无法排除伪造」而丢弃的——这个数高说明海外 DoH 不可达。

## 已知限制（别把这些当成 bug）

1. **探活是在 GitHub Actions 上跑的**（Azure，美国）。它证明的是「这个 IP 在全球视角能握手成功」，不等于「你在国内一定能连」。被墙站点的 IP 从美国探测是通过的，但在国内仍然可能连不上——这不是这条流水线能解决的。
2. **GitHub Actions 没有 IPv6 出口**，所以 IPv6 只能做 DoH 校验，不能证明 v6 路径真的可达。如果你要在纯 v6 环境里用，建议自己再补一层本地探测。
3. **GitHub、Steam 商店/社区、Epic 本身没有 AAAA 记录**（实测：`github.com`、`store.steampowered.com`、`www.epicgames.com` 查 AAAA 都是空的）。所以这些平台在这份文件里只有 IPv4，这是上游事实，不是脚本漏了。真正能双栈的是 GOG、`raw.githubusercontent.com`、以及 Steam 的两个 CDN 域名。
4. **首次运行的丢弃率会很高**（2 万多域名的老表里失效 IP 一大片），这是正常的过滤结果。
5. **DoH 的信任分层**：海外解析器（Cloudflare / Google）用于「生成新记录」，国内解析器（AliDNS）只用于「核对上游已有记录」。如果 Action 运行环境连不上 Cloudflare/Google，`doh-refreshed` 会变成 0，只保留上游自带的 v6——这是安全降级，不是故障。

## 安全边界

- 全程只读上游、只写自己仓库的 `dist/`，不碰你路由器的 `/etc/hosts`。
- 任一源抓取失败不会导致线上文件变空：域名数低于 `--min-domains`（默认 500）直接放弃本轮构建，保留旧文件。
- 想审计某天为什么某个域名解析错了，直接看 `dist/selected.csv` 对应行。
