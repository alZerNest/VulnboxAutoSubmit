# VulnboxAutoSubmit

漏洞盒子漏洞报告自动提交工具。程序固定读取当前目录下的 `config.yaml`，漏洞数据默认读取 `bugs.xlsx`，也可以通过 `--data` 指定其他 Excel 或 CSV 文件。

## 安装

在工程目录执行：

```powershell
python -m pip install -r requirements.txt
```

## 第一次使用

### 1. 设置认证信息

打开 `config.yaml`，在 `auth` 区块填写认证信息：

```yaml
auth:
  token: "在这里粘贴浏览器中的 vulbox_token"
  uuid: ""
  cookies: ""
```

说明：

- `auth.token`：必填，填写浏览器 Cookie 中 `vulbox_token` 的 Value。
- 不要粘贴 `vulbox_token=`，也不要添加 `Bearer ` 前缀。
- `auth.uuid`：可选，请求头中的 `uuid`。
- `auth.cookies`：可选，其他 Cookie，格式为 `name=value;name2=value2`。

也可以使用环境变量临时覆盖配置文件中的认证信息：

- `VULBOX_TOKEN`
- `VULBOX_UUID`
- `VULBOX_COOKIES`

环境变量优先级高于 `config.yaml`。`config.yaml` 包含敏感认证信息，已被 `.gitignore` 忽略，不要上传到公共仓库。

### 2. 填写漏洞信息

默认读取 `bugs.xlsx`，也可以使用 `--data` 指定其他数据文件。每一行是一条独立漏洞，项目、类别、类型、等级、地区和行业都必须按行填写，不能依赖统一默认值。

支持 `.xlsx`、`.xls` 和 `.csv` 文件：

```powershell
python main.py --data other-bugs.xlsx
```

不指定 `--data` 时等同于：

```powershell
python main.py --data bugs.xlsx
```

文件路径相对于工程目录解析。

| 列名 | 填写说明 |
| --- | --- |
| `项目名称` | 页面显示的项目名称，用于人工核对 |
| `项目ID` | 项目接口 ID，即 `task_id`，必须填写数字 |
| `漏洞标题` | 漏洞标题 |
| `漏洞类别` | `事件型漏洞` 或 `通用型漏洞`，也支持接口数字值 |
| `厂商名称` | 厂商名称 |
| `厂商域名` | 厂商域名或目标域名/IP |
| `漏洞类型` | 平台对应的漏洞类型 ID，可填写多个并用逗号分隔，例如 `1,9,732` |
| `漏洞等级` | `严重`、`高危`、`中危` 或 `低危`，也支持接口数字值 |
| `漏洞简述` | 漏洞概况和危害 |
| `复现步骤` | 漏洞复现步骤 |
| `修复建议` | 修复方案 |
| `所属地区` | 省份和城市，用逗号分隔，例如 `河北,沧州` |
| `所属行业` | 行业大类，例如 `百货/批发/零售` |
| `行业细分` | 行业细分，例如 `批发`，可留空 |
| `漏洞URL/位置` | 漏洞 URL 或功能点，可留空 |
| `影响参数` | 受影响参数，可留空 |
| `漏洞POC请求包` | POC 请求包，可留空 |

其中 `项目名称` 仅用于人工核对，实际提交使用同一行的 `项目ID`。`漏洞类型` 必须填写平台对应的数字 ID，不能只填写类型名称。

也兼容旧英文列名和部分中文列名，例如 `bug_title`、`bug_firm_name`、`domain`、`bug_url`、`bug_paper`、`repetition_step`、`fix_plan`。

### 3. 配置说明

`config.yaml` 中以下字段由每条 Excel 记录单独提供：

- 项目名称、项目ID
- 漏洞类别
- 漏洞类型
- 漏洞等级
- 所属地区
- 所属行业
- 行业细分

这样不同漏洞可以分别提交到不同项目，使用不同类别、类型、等级、地区和行业。

`config.yaml` 只对接口地址、超时时间、认证信息和不随漏洞变化的技术字段进行配置。

## 运行

在工程目录执行：

```powershell
python main.py
```

无参数运行会读取 `config.yaml` 和 `bugs.xlsx`，直接提交全部尚未成功的记录。成功记录会写入 `submitted.txt`，再次运行时自动跳过，避免重复提交。

只检查数据、不发送请求：

```powershell
python main.py --dry-run
```

只处理前 N 条：

```powershell
python main.py --limit 1
```

指定其他数据文件并预览：

```powershell
python main.py --data other-bugs.xlsx --dry-run
```

## 文件说明

- `client.py`：接口请求和认证处理
- `main.py`：主程序、Excel 读取和逐行字段映射
- `models.py`：请求数据模型
- `config.yaml`：本地配置和认证信息，不要上传
- `config.yaml.example`：无真实认证信息的配置模板
- `bugs.xlsx`：默认漏洞提交数据
- `bugs.example.xlsx`：漏洞数据模板
- `submitted.txt`：提交记录

真实 Token、漏洞数据和抓包文件不要上传或提交到公共仓库。
