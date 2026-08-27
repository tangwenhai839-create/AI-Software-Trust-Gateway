# ASTG 确定性评分体系规范 (`mvp-static-v1`)

## 1. 评分设计哲学

- **可复现性 (Reproducibility)**：相同版本的目标代码、规则集和配置，必须 100% 确定性输出相同的安全分与等级。
- **证据优先 (Evidence First)**：任何扣分项均需回溯到具体文件行号或漏洞情报。
- **禁止单点定罪与单点脱罪**：单个关键词不直接定罪；AI 的好评绝不能抵消已证实的高危代码特征。

## 2. 权重分配 (`mvp-static-v1`)

在 MVP 纯静态阶段，权重分配如下：

| 评估维度 | 权重 | 评估依据 |
|---|---:|---|
| **静态代码风险** | 45% | 动态执行 (eval/exec)、命令执行、敏感文件访问、隐蔽外发 |
| **依赖与供应链漏洞** | 35% | OSV / CVE 漏洞数据库匹配、漏洞严重度 (CVSS) |
| **项目溯源与信誉** | 15% | 开源许可证、社区 Star/Fork 关注度、创建时间 |
| **AI 综合语意解释** | 5% | 软件声明用途与发现项的语意匹配概率 (限制上限 5%) |

## 3. 计算公式

$$\text{weighted\_risk} = \frac{\sum (\text{Component Risk} \times \text{Weight})}{\sum \text{Applicable Weight}}$$

$$\text{raw\_safety\_score} = \text{round}(100 - \text{weighted\_risk})$$

## 4. 强制性安全分上限 (Score Caps)

为防止高危样本因其他维度拉高总分，系统内置硬性分数上限：

1. **Critical Finding Cap**：若存在已证实的 Critical 静态发现，`safety_score = min(safety_score, 39)`（强制判定为高风险）。
2. **High Finding Cap**：若存在已证实的高危发现，`safety_score = min(safety_score, 69)`（最高为中风险）。
3. **Critical CVE Cap**：若存在严重依赖漏洞，`safety_score = min(safety_score, 49)`。

## 5. 等级划分标准

- **90 – 100 [SAFE]**：安全 (低观测风险)
- **70 – 89 [LOW]**：低风险 (可在受限环境运行)
- **40 – 69 [MEDIUM]**：中风险 (需人工代码复核)
- **0 – 39 [HIGH]**：高风险 (默认阻止运行)
