# devsecops-demo — 一条带门禁、供应链感知的交付流水线

一个面向生产形态的demo：把安全扫描器变成**可靠的控制点**——PR 时门禁、一次构建 + digest promotion、签名与加注的制品、策略即代码门禁（支持过期豁免）、运行时验证（DAST + 部署后冒烟测试），以及人工审批的promote路径——运行在Jenkins 实例上，目标是一个故意植入漏洞的 Flask 应用。

**CI/CD pipeline：**

<img width="828" height="2122" alt="Untitled Diagram drawio (1)" src="https://github.com/user-attachments/assets/05e6032f-c174-4822-92a3-4f5bfb0cbbcc" />

## 工具集成

| 方法            | 工具                                                  | 阶段                   | 门禁行为                                                 | 决策 / 权衡                                                |
| --------------- | ----------------------------------------------------- | ---------------------- | -------------------------------------------------------- | ---------------------------------------------------------- |
| 密钥扫描        | Gitleaks `v8.21.2`（+ 组织规则 `demo-api-token`）     | CI                     | **无条件失败**（`fail_tools`）                           | 密钥泄露就是泄露，与严重级别无关                           |
| SAST            | Semgrep `1.155.0`（`p/security-audit` + 组织规则）    | CI                     | Critical 与特定漏洞类型失败，High 告警                   | Semgrep 轻量但偏浅(相比于codeql, joern)，对演示应用足够    |
| SCA / SBOM      | Syft `v1.51.0` + Grype `v0.115.0`                     | CI（源码）+ CD（镜像） | 默认严重级别 + **KEV/EPSS 覆盖**                         | SBOM 优先：产出 CycloneDX，Grype 消费 SBOM；持久化清单     |
| IaC / 清单扫描  | Trivy `0.74.0` config + **自定义 Rego**（DS-001/2/3） | CI                     | 组织严重级别**覆盖**厂商级别；CRITICAL Rego = 失败       | 策略即代码：组织风险 > 厂商标签                            |
| 镜像扫描        | Trivy `0.74.0` + **OpenVEX**                          | CD 签名前              | Gate #1，签名之前拦截                                    | 绝不给未过门禁的镜像签名 / 加注                            |
| 镜像签名 + 加注 | Cosign（密钥）                                        | CD                     | 对 digest 签名 + SBOM `cyclonedx` 加注，随后**自验**     | 身份（签名）≠ 清单（SBOM），两条信息分开证明               |
| Chart 来源验证  | Helm `package --sign`（GPG）                          | CD                     | 用**已提交**的公钥执行 `helm verify`                     | 确保部署单元的真实性；任何篡改都会被检出                   |
| DAST            | ZAP baseline，集群内 Job                              | CD（staging）          | 更严的 `dast:` 策略——high=失败，medium=告警              | 线上漏洞值得更严的门禁：live端点上的发现比静态命中严重得多 |
| 运行时验证      | k8s 探针 + 集群内smoke Job                            | CD                     | 硬失败阶段，带诊断兜底                                   | 探针 ≠ 业务逻辑；smoke测试证明应用真的能工作               |
| 策略门禁        | `tools/{normalize,gate,report}.py`                    | CI + CD                | 每个门禁一个决策点；退出码 0/1/2/3 → 通过/告警/失败/错误 | 读取扫描报告，**由门禁决定流水线状态**，扫描器本身不做判断 |

---

# 总览

## 持续集成（`Jenkinsfile.ci`）

PR 与 push 到 `main` 时触发。阶段串行执行以保证演示的确定性；**不携带任何凭据**——PR 层不可信。

<img width="1416" height="111" alt="image" src="https://github.com/user-attachments/assets/16130cdf-172a-4b7f-aeb6-60edc08ae201" />

1. **Clone + unit tests** — ruff + pytest

   _Why_：先做最便宜的控制；不扫描坏代码。

2. **Dependency report** — Syft → CycloneDX SBOM → Grype → 报告，上传到制品库。

   _Why_：SBOM 优先；持久化清单，漏洞库更新后可以随时重新评估。

3. **Static analysis** — gitleaks（密钥）、semgrep（反模式：拼接 SQL、MD5）、trivy（IaC，内置规则 + 组织 Rego）。

   _Why_：通用规则（semgrep `p/security-audit`、trivy 内置规则）只能发现厂商认为有风险的东西；组织规则承载的才是**这个代码库**真正关心的风险（我们的密钥格式、不安全的 SQL、MD5）。

4. **Gate** — `normalize → gate → report`；`fail`/`error` → FAILURE，`warn` → UNSTABLE。

   _Why_：扫描器串行执行是为了演示的确定性——生产环境应并行。尽力报告尽可能多的问题，由门禁决定流水线最终状态。

## 可配置门禁

`security/policy.yaml` — 动作优先级：**exceptions**（指纹匹配）> **分类工具**（gitleaks）> **KEV/EPSS** > **默认严重级别**（critical=失败，high=告警，medium=通过）。

_Why_：用高度可配置的策略去适配不同组织的合规要求。

## 持续交付（`Jenkinsfile.cd`）

手动、参数化触发。一次构建 → 一个 digest → 带门禁的promotion。

<img width="1434" height="75" alt="image" src="https://github.com/user-attachments/assets/0d0b2c9e-4582-4dc8-8aa6-0406657cfe33" />

1. **Build & push image ONCE** — 3 个 tag（`<sha8>-<BUILD_NUMBER>`、`latest`、`<APP_VERSION>`），记录 digest。

   _Why_：不可变身份；实际部署的永远只有 digest。

2. **Image SBOM + scan + GATE #1** — syft 生成 SBOM，trivy 镜像扫描（CRITICAL/HIGH，VEX 过滤）。

   _Why_：被扫描的对象就是即将被签名的那个artifact；未过门禁的镜像绝不进入签名环节。

3. **Sign + verify** — cosign 签名 + SBOM 加注，并用公钥验证；helm chart GPG 签名 + 验证。

   _Why_：两条相互独立的信任链。

4. **Deploy staging + DAST + GATE #2** — 签名 chart 部署 digest 固定的镜像；集群内 ZAP baseline；门禁综合评估静态 + DAST 发现（更严的 `dast:` 策略）。

   _Why_：live端点上的运行时发现属于不同的风险类别；生产环境永远不会被主动扫描。

5. **Verify + manual promote to production** — smoke Job（健康检查、CRUD、搜索）+ 证据留档；人工审批；部署**同一个** digest。

   _Why_：promotion是明确的人工决策；确保部署的 digest 是经过扫描和信任的。

## 安全策略与 CI failure 示例

| `policy.yaml` 规则                            | 本仓库示例                                                        | CI 结果                                          |
| --------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------ |
| `fail_tools: [gitleaks]`                      | `ds-demo-<32hex>` token（种子，`app/config.py`）                  | 构建**失败**——分类性规则，任何exception都无效    |
| `fail_rule_classes`（SQLi/SSRF/反序列化/RCE） | `/demo/unsafe-search` 拼接 SQL（种子，`app/db.py:60`）            | 构建**失败**——特定漏洞类型即使厂商标 High 也阻断 |
| `fail_when` KEV / EPSS ≥ 0.9                  | （元数据驱动；当前无匹配的发现）                                  | High + KEV → 按 Critical 对待                    |
| `severity_defaults` high → warn               | MD5 密码哈希（种子，`app/app.py:43`）                             | **UNSTABLE**，除非被豁免                         |
| 豁免（过期、指纹匹配）                        | EXC-0042（MD5，2026-09-13 过期，工单 SEC-221）                    | 发现被**豁免**；写入审计行；过期后自动闭锁失败   |
| VEX（`--vex`）                                | gunicorn CVE-2024-6827 = `not_affected`（不修复但继续前进的案例） | 扫描时过滤——带着证据                             |
| 闭锁门禁                                      | 缺少 `trivy.sarif` / 无发现输入                                   | **ERROR**——坏掉的扫描永远不会看起来像通过        |

## 端到端演示

完整演示流程见 **[docs/steps/steps.md](docs/steps/steps.md)**。

## 环境搭建

按 **[SETUP_DEMO.md](SETUP_DEMO.md)** 操作——Docker Hub 仓库 + token、Jenkins agent 上的 kind 集群、cosign + helm GPG 密钥、GitHub App、Jenkins 插件/凭据（凭据 ID：`dockerhub`、`cosign-key`、`cosign-pub`、`kind-kubeconfig`、`helm-signing-key`），以及两个 multibranch job。

## 仓库结构

```
Jenkinsfile.ci / Jenkinsfile.cd   两条流水线（CI = 源码门禁，CD = 供应链 + 部署）
app/                              故意植入漏洞的 Flask 应用（token、SQLi、MD5、gunicorn CVE）
security/                         policy.yaml（门禁）、exceptions.yaml（过期豁免）、gitleaks/semgrep/trivy-rego/kyverno 规则、VEX
tools/                            normalize.py · gate.py · report.py —— 策略引擎
deploy/helm/notes-app/            单一版本化 chart：应用 + DAST Job + 冒烟 Job + regcred
deploy/helm/keys/public.asc       已提交的 chart 签名公钥（私钥对是 Jenkins 凭据）
docs/                             pipeline-stages.md（阶段细节）· steps/（端到端演示）· DESIGN.md · VEX.md
SETUP_DEMO.md                     环境搭建指南
```

# Threat Model the Demo Flask App - A Practice

## Trust Boundaries

In order of trust:

1. Internet/attacker
2. Jenkins agent + containers
3. docker registry, kind cluster
4. Flask app process
5. SQLite DB, secrets, signing keys

## Assets

DREAD-style value ranking:

| Asset                                  | Value    | Notes                                |
| -------------------------------------- | -------- | ------------------------------------ |
| Signed image digest + SBOM attestation | Critical | verify-image stage in CD enforces it |
| Notes DB                               | Medium   | demo data                            |
| APP_SECRET_KEY,ADMIN_PASSWORD_HASH     | Medium   | env-driven                           |

## Dataflow

<img width="790" height="473" alt="image" src="https://github.com/user-attachments/assets/c44c3864-b98c-49c3-8dd9-f5d235d9e465" />

## STRIDE

| Threat                 | Risk                                                                                                                            | Pipeline control (countermeasure)                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Spoofing               | 1) /login+/admin accept a password query param, md5 hash is crackable, no rate-limiting; 2) Image in registry could be replaced | 1) Semgrep no-md5-hashing -> gate fail -> block CI; 2) cosign key signing + verification, Helm chart Sigining |
| Tampering              | 1) /demo/unsafe-search f-string SQLi; 2) SBOM drift                                                                             | 1) Semgrep no-formatted-sql -> gate fail -> block CI; 2) SBOM attested by cosign                              |
| Repudiation            | No audit logging for POST /notes (anonymous create)                                                                             | no countermeasure; future story: audit log                                                                    |
| Information Disclosure | /export/notes is unauthenticated bulk data exfiltration surface                                                                 | no countermeasure; future story: authentication                                                               |
| Denial of Service      | /demo/unsafe-search '%' wildcard + unbounded LIKE condition + no rate-limiting                                                  | no countermeasure; future story: DDoS protection                                                              |
| Elevation              | -                                                                                                                               | -                                                                                                             |
