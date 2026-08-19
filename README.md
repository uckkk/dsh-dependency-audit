# dsh-dependency-audit · 依赖安全审计

扫描项目依赖的安全状态：① 通过 **OSV.dev** 查询每个依赖的已知漏洞；② 对比 **npm registry** 检测过期依赖。纯 Node 实现，仅需联网访问 osv.dev 与 npm registry。

## 提供的工具

| 工具 | 作用 |
|---|---|
| `audit_vulnerabilities` | 批量查询 OSV.dev，返回受影响依赖的漏洞 ID、严重级、摘要、修复版本 |
| `audit_outdated` | 对比已安装 vs 最新版本，返回过期依赖与升级幅度（major/minor/patch） |

## 安装

```bash
dsh plugin add dsh-dependency-audit
```

安装后在 profile 的 `package.json` 的 `dsh.profile.bundles` 中加入 `"dsh-dependency-audit"`。

## 用法示例

```
帮我审计这个项目依赖有没有已知漏洞
→ 调用 audit_vulnerabilities(root="/workspace")

哪些依赖过期了，升级幅度多大
→ 调用 audit_outdated(root="/workspace")
```

## 说明

- 漏洞数据来自 [OSV.dev](https://osv.dev)（开源漏洞数据库，覆盖 GitHub Advisory 等来源），查询免费无需 key。
- 只检查已安装（能解析出确切版本）的依赖；`node_modules` 里解析不到的依赖会跳过。
- 与 `dsh-license-guard`（许可证合规）、`dsh-secret-scan`（密钥扫描）构成安全三件套。

## 安装

```bash
dsh plugin add github:uckkk/dsh-dependency-audit
```

> 安装即在本机运行第三方代码，请自行审阅源码。

## 安装

```bash
dsh plugin add github:uckkk/dsh-dependency-audit
```

## 使用

安装后在会话中调用该插件注册的工具即可。

## 许可

MIT
