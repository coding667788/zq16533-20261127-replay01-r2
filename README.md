# ProofCask

ProofCask 是一个仅使用 Python 3.12 标准库的离线审计封存清单比对工具。它比较两批可能具有不同目录树形的载荷清单，输出新增、缺失、等价、冲突、不确定项，以及可独立复核的最小 Merkle 路径；并可把多个指定证物和两份根之间的差异压缩成共享节点 capsule。

设计重点：

- **规范 UTF-8 JSON**：所有参与哈希和 HMAC 签名的对象都使用无空白、键排序、`ensure_ascii=False` 的紧凑 JSON。
- **叶子/内节点分域 SHA-256**：
  - 叶子：`SHA256("proofcask:leaf:v1\n" + canonical_json(leaf))`
  - 内节点：`SHA256("proofcask:branch:v1\n" + canonical_json(branch))`
  - 载荷摘要：普通 `SHA256(payload_bytes)`，编码为 `sha256:<hex>`。
- **稳定 `leaf_id` 优先**：不会因为载荷摘要相同就把不同证物 ID 合并。相同摘要、不同 `leaf_id` 是合法的独立证物。
- **路径与叶子分离承诺**：叶子对象提交 `leaf_id/payload_digest/metadata`；路径分量和位置由 branch 节点的有序 `{name,hash}` 子项提交。
- **签收映射**：改名必须有 HMAC-SHA256 签收记录；后续有效签收的 `revoke` 更正会撤销映射。
- **允许“不确定”**：中间页缺失、映射缺失/失效/撤销、密钥不可用时，不强行断言等价。
- **最小路径证明**：每条结论都带 OLD/NEW 的叶子证明或缺页证明。
- **共享节点 capsule**：多条路径共用的 branch 节点只放入全局 `node_pool` 一次；验证器根据两个受信根独立重算。

## 目录

```text
proofcask/              标准库 Python 包
  cli.py                reconcile / capsule / verify 命令
  manifest_core.py      规范哈希、清单构造、遍历、最小路径证明与验证
  mapping.py            签收映射、HMAC 验证、撤销处理
  reconcile.py          OLD/NEW/MAP 比对分类
  capsule.py            共享节点 capsule 构造与独立验证
  fixtures_builder.py   合成夹具生成器
tests/
  test_proofcask.py     可直接运行的 unittest 和变异测试
tools/
  build_fixtures.py     生成 fixtures/
fixtures/               已生成的 Windows 友好合成夹具
```

## 快速开始

以下命令在仓库根目录的 PowerShell 中运行。也可以用 `.\proofcask.cmd ...` 代替 `python -m proofcask ...`。

```powershell
python --version          # 需要 Python 3.12
python tools\build_fixtures.py
python -m unittest discover -s tests -v
```

运行单个测试文件也可以：

```powershell
python tests\test_proofcask.py -v
```

### 1. 比对两批清单

```powershell
python -m proofcask reconcile `
  fixtures\old_manifest.json `
  fixtures\new_manifest.json `
  fixtures\mappings.json `
  --out fixtures\reconcile-report.json
```

标准输出和 `--out` 文件都是 UTF-8 JSON。当前合成夹具的摘要是：

```json
{
  "equivalent": 8,
  "added": 1,
  "missing": 1,
  "conflicting": 3,
  "indeterminate": 3,
  "old_tree_gaps": 0,
  "new_tree_gaps": 1
}
```

### 2. 构造 capsule

`INCLUDE` 可以是：

- 逗号分隔的叶子 ID：`"L-REPORT,L-SHARED-1"`
- include JSON/TXT 文件，例如 `fixtures\include.json`
- `@include.txt`
- `ALL`

`REF` 可以是 reference JSON，也可以是 ProofCask `reconcile` 输出报告。

```powershell
python -m proofcask capsule `
  fixtures\include.json `
  fixtures\reference.json `
  --out fixtures\capsule.json
```

### 3. 独立复核 capsule

```powershell
python -m proofcask verify fixtures\capsule.json `
  --map-key fixtures\mapping.key `
  --payload-dir fixtures\payloads
```

成功时进程退出码为 `0` 且 JSON 中 `"ok": true`；证明或变异导致的验证失败输出可读错误码并以退出码 `1` 结束。输入文件/命令用法错误输出 `{"ok": false, "error": ...}` 并使用退出码 `2`。

> Windows PowerShell 5 的 `>` 重定向可能写成 UTF-16。需要保存 JSON 时优先使用 `--out`，或使用 `| Set-Content -Encoding utf8`。

## 清单格式

清单是内容寻址节点库：

```json
{
  "schema": "proofcask.manifest/v1",
  "batch_id": "BATCH-OLD-SYNTHETIC",
  "root": "sha256:...",
  "nodes": {
    "sha256:...": {
      "kind": "leaf",
      "leaf_id": "L-STABLE",
      "payload_digest": "sha256:...",
      "metadata": {"custodian": "clerk-a"}
    },
    "sha256:...": {
      "kind": "branch",
      "children": [
        {"name": "note.txt", "hash": "sha256:..."}
      ]
    }
  }
}
```

规则：

1. `nodes` 的键必须等于节点规范预像重算出的 SHA-256。
2. branch 的 `children` 必须按 `name` 的 Unicode/码点规范升序排列，名称不得重复。
3. 逻辑路径使用 `/` 分隔，必须是相对路径；不允许空分量、`.`、`..`、反斜杠或控制字符。
4. 父节点通过 `{name, hash}` 提交子节点。即使子页没有随清单提供，父节点仍可证明“根在某路径承诺了某个缺失哈希”。
5. 未被根引用的节点会被忽略；所有提供的节点仍会做哈希/结构校验。

## reconcile 分类

每个条目位于一个顶层数组中：

| 顶层数组 | 含义 | 常见 `reason_code` |
|---|---|---|
| `equivalent` | 有可复核证据断言等价 | `same_leaf_commitment`, `verified_rename` |
| `added` | NEW 中有稳定 ID，OLD 中无存在证据或缺页线索 | `leaf_id_absent_from_old` |
| `missing` | OLD 中有稳定 ID，NEW 中无存在证据或缺页线索 | `leaf_id_absent_from_new` |
| `conflicting` | 双方证据发生确定冲突 | `duplicate_exhibit`, `payload_digest_mismatch`, `metadata_mismatch`, `payload_and_metadata_mismatch` |
| `indeterminate` | 证据不足或授权不可信，不能断言相同 | `missing_intermediate_node`, `rename_mapping_missing`, `rename_mapping_revoked`, `mapping_signature_invalid`, `mapping_key_unavailable` |

每个条目的 `evidence.old` / `evidence.new` 是最小路径证明；缺页时相应证明的 `subject_kind` 为 `missing_node`。重复证物使用 `evidence.old_all` / `evidence.new_all` 给出全部位置，而不是只挑一个。

报告的 `observations.legal_same_digest_exhibits` 单独列出“摘要相同但 `leaf_id` 不同”的合法证物组；`observations.shared_subtrees` 列出两批根中哈希完全相同的最大共享子树。

## 映射记录与撤销

映射包格式见 `fixtures/mappings.json`。每条 rename/revoke 记录包含 `record_id`、`op`、时间、签收人和 `signature`。签名内容是去掉 `signature` 字段后的规范记录：

```text
HMAC_SHA256(key, "proofcask:mapping-record:v1\n" + canonical_json(record_without_signature))
```

密钥解析顺序：

1. CLI `--map-key`（可以是密钥文本或密钥文件路径）
2. 环境变量 `PROOFCASK_MAP_KEY`
3. MAP 中的 `map_key` 文本
4. MAP 中 `key_file`（相对于 MAP 文件目录）

合成夹具的 `fixtures/mapping.key` 是公开的测试密钥，只用于演示和 unittest；生产环境必须通过独立信任通道管理 HMAC 密钥或替换为非对称签收。

## capsule 如何压缩和防冒充

capsule 包含：

- 两个受信根 `roots.old/new`；
- 规范排序的 `included` 证物 ID；
- `proofs.old.targets` 和 `proofs.new.targets`；
- 一个按节点哈希排序、两边共享的 `node_pool`；
- 映射签收记录；
- 与 reconcile 对应的精简 `delta.entries`；
- 合法共享子树描述。

多个目标经过相同 branch 节点时，该节点在 `node_pool` 中只出现一次。验证器对每个池节点重算哈希，然后从根开始按 `path` 向下检查：

1. 当前 branch 必须在池中且哈希正确；
2. 路径分量必须能在该 branch 的有序子项中找到；
3. 最后一个分量承诺的哈希必须等于目标叶子/缺页哈希；
4. 目标叶子的 `leaf_id/payload_digest/metadata` 必须重算出 `target_hash`。

未包含对象的完整内容不会进入 capsule，但它的 `{name,hash}` 仍在路径 branch 中并最终提交到根。替换未包含对象会改变其哈希，进而导致：

- 池节点 `NODE_HASH_MISMATCH`；
- 或父节点 `PARENT_HASH_MISMATCH`；
- 或最终 `ROOT_MISMATCH` / `TREE_POSITION_MISMATCH`。

因此没有受信根或 HMAC 密钥时，验证器仍可验证 Merkle 证明本身；改名授权验证需要提供映射密钥。`--payload-dir` 可进一步用实际证物字节复核载荷摘要，支持 `<digest-hex>.bin` 和 `<leaf_id>.bin` 等候选文件名。

## 变异测试与可读错误码

`tests/test_proofcask.py` 对同一份有效证明逐一做以下变异：

| 变异 | 预期错误码 |
|---|---|
| 颠倒/交换 `steps` 或 capsule targets 顺序 | `PROOF_ORDER_INVALID` |
| 篡改 claimed path / 树位置 | `TREE_POSITION_MISMATCH` |
| 篡改 `leaf_id` | `LEAF_ID_MISMATCH` |
| 篡改 `payload_digest` | `PAYLOAD_DIGEST_MISMATCH` |
| 篡改未包含兄弟节点摘要 | `PARENT_HASH_MISMATCH` 或 `NODE_HASH_MISMATCH` |

错误对象形态：

```json
{
  "code": "LEAF_ID_MISMATCH",
  "message": "proof leaf_id does not match committed leaf.leaf_id",
  "details": {"proof_leaf_id": "L-MUTATED-ID", "target_leaf_id": "L-REPORT"}
}
```

## 合成夹具覆盖的场景

- `shared/`：OLD/NEW 完全一致的合法共享子树；
- `gap/2024/index.txt`：NEW 清单故意缺少中间 branch 页 `gap/2024`，OLD 保留完整证明；
- `L-REPORT`：已签收改名为 `archive/quarterly-renamed.txt`；
- `L-REPORT-COPY`：另一个稳定 ID，且与 `L-REPORT` 有相同载荷摘要，仍在 `copies/` 原位；
- `L-CORRECTED`：第一次错误映射被签收撤销，随后新的签收映射生效；
- `L-REVOKED`：改名映射后来被有效撤销，结论为不确定；
- `L-UNMAPPED`：没有映射，结论为不确定；
- `L-DUP`：同一 `leaf_id` 出现在两个 NEW 路径，构成 `duplicate_exhibit`；
- `L-META`：载荷摘要相同但 custodian/label 元数据不同，构成 `metadata_mismatch`；
- `L-TWIN-A/L-TWIN-B`：相同摘要、不同稳定证物 ID，是合法的摘要共享。

## 信任边界

ProofCask 能证明“所给叶子/缺页哈希包含在某个根中”以及“规范内容重算出该哈希”。`roots.old/new` 本身必须来自带外可信封存值；如果直接信任并读取清单中的 `root` 字段，它只证明清单内部一致。映射 HMAC 密钥也必须通过受控渠道分发。工具不会联网、不执行外部进程（unittest 的 CLI 烟雾测试除外），适合隔离的普通 Windows CPU 环境。
