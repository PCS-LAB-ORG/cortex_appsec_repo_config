# Cortex AppSec Repository Configuration Engine (v1.0)

A deterministic, multi-threaded Configuration-as-Code automation engine designed to synchronize targeted branches and
Application Security scanner settings (SCA, IAC, Secrets) across your Palo Alto Networks Cortex platform.

This engine enables security teams to enforce global baselines, selectively override scanner functionalities per
repository, and manage tracking targets at scale without manually modifying settings in the Cortex UI.

---

## ✨ Features

* **Configuration-as-Code**: Centralize and version-control your Application Security scan rules, path exclusions,
  pull-request blockers, and target branch tracking in a standard local YAML/JSON file.
* **Granular Target Overrides**: Establish strong security baselines globally, while selectively turning off noisy
  scanners or tracking custom release branches for specific repositories.
* **Non-Destructive Updates**: Dynamically inherits and preserves currently tracked branches if a configuration only
  updates scanner rules, preventing accidental erasure of active targets.
* **Automated Exclusions**: Prevents the tool from tracking or modifying ephemeral integration pipelines (e.g.,
  `CORTEX_CLI`, `GITHUB_ACTIONS`, `JENKINS`) using customizable ignore lists.
* **Failsafe Dry-Runs**: Built-in safeguards default to dry-run logic, explicitly calculating and formatting proposed
  modifications locally before any active mutations happen.
* **CLI Operational Mode**: Config-less execution allows deployment via pipeline by injecting global targets directly
  via the command line (e.g., `--scan-iac false`).

---

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/PCS-LAB-ORG/cortex_appsec_repo_config.git
   cd cortex-scan-automation
   ```
2. Initialize virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\\Scripts\\activate
   pip install -r requirements.txt
   ```

---

## ⚙️ Configuration

### 1. Environment Variables (`.env`)

Configure the essential base credentials and operational targets. Note that most execution constraints and toggles can
also be passed dynamically as CLI arguments (see the precedence table below):

```env
# Credentials & Target Endpoint
CORTEX_API_ID=your_key_id
CORTEX_API_SECRET=your_secret_key
CORTEX_API_URL=https://api-yourtenant.paloaltonetworks.com

# Engine Control 
SCAN_CONFIG_FILE=config.yaml
EXECUTE_CHANGES=false
```

### 2. Standard Schema (`config.yaml`)

Reconciled sequentially from top to bottom (**First-Match-Wins**).

```yaml
global_config:
  primary_branch: "main"
  scanned_branches:
    - "develop"
  scan_config:
    scanners:
      iac:
        is_enabled: true
      sca:
        is_enabled: true

repo_overrides:
  # Disables SCA scanning for this frontend repository only
  - org: "my-company-org"
    repo: "frontend-react-app"
    scan_config:
      scanners:
        sca:
          is_enabled: false
```

---

## ⚖️ CLI Arguments & Variable Precedence

All variables are parsed following a strict precedence hierarchy: **Command Line Arguments (Highest)** ➔ **OS
Environment Variables** ➔ **Local `.env` File (Lowest)**.

| Argument                | Environment Equivalent  | Description                                                                         |
|:------------------------|:------------------------|:------------------------------------------------------------------------------------|
| `--execute`             | `EXECUTE_CHANGES=true`  | **MUST be passed to apply modifications.** Standard dry-run is enforced if omitted. |
| `--config`              | `SCAN_CONFIG_FILE`      | Local path pointing to YAML/JSON configuration.                                     |
| `--api-id`              | `CORTEX_API_ID`         | API Key ID.                                                                         |
| `--api-secret`          | `CORTEX_API_SECRET`     | API Key Secret.                                                                     |
| `--api-url`             | `CORTEX_API_URL`        | Base API target URL.                                                                |
| `--api-timeout`         | `CORTEX_API_TIMEOUT`    | Global HTTP timeout threshold in seconds (defaults to `30`).                        |
| `--log-level`           | `LOG_LEVEL`             | Logging verbosity level (e.g., `INFO`, `DEBUG`).                                    |
| `--exclude-sources`     | `EXCLUDE_SOURCES`       | Comma-separated list of integration sources to ignore (e.g., `CORTEX_CLI`).         |
| `--export-snapshot`     | `EXPORT_SNAPSHOT=true`  | Triggers a baseline export of current platform state, then exits.                   |
| N/A                     | `EXPORT_SNAPSHOT_FILE`  | Format/Path for the snapshot file (e.g., `snapshot_%Y-%m-%d.yaml`).                 |
| N/A                     | `SAVE_PROPOSED_CHANGES` | Save intended modifications to `proposed_changes.json` (`true`/`false`).            |
| N/A                     | `MAX_THREADS`           | Number of concurrent execution threads (defaults to `5`).                           |
| N/A                     | `CORTEX_API_TYPE`       | Cortex authentication protocol (`ADVANCED` or `STANDARD`).                          |
| `--primary-branch`      | N/A                     | Global primary branch target (Config-less mode).                                    |
| `--scanned-branches`    | N/A                     | Comma-separated list of secondary branches (Config-less mode).                      |
| `--excluded-paths`      | N/A                     | Comma-separated list of paths to exclude from scanning (Config-less mode).          |
| `--scan-iac`            | N/A                     | Enable/Disable Infrastructure-as-Code scans (`true`/`false`).                       |
| `--scan-sca`            | N/A                     | Enable/Disable Software Composition Analysis scans (`true`/`false`).                |
| `--scan-secrets`        | N/A                     | Enable/Disable Secrets scanning (`true`/`false`).                                   |
| `--pr-scanning`         | N/A                     | Enable/Disable Pull Request checks (`true`/`false`).                                |
| `--pr-block-on-error`   | N/A                     | Enable/Disable blocking pull request actions on errors (`true`/`false`).            |
| `--tag-module-blocks`   | N/A                     | Enable/Disable tagging for module blocks (`true`/`false`).                          |
| `--tag-resource-blocks` | N/A                     | Enable/Disable tagging for resource blocks (`true`/`false`).                        |
| `--secret-validation`   | N/A                     | Enable/Disable secret validation (`true`/`false`).                                  |
| `--secret-git-history`  | N/A                     | Enable/Disable git history scanning for secrets (`true`/`false`).                   |

---

## 💻 Operational Modes

### 1. Active Dry-Run (Default Safety Posture)

Evaluates differences and generates local logs without modifying any live settings:

```bash
python cortex_appsec_repo_config.py
```

This writes all calculated branch and scanner changes to `proposed_changes.json`.

### 2. Direct Sync Execution

Enables network mutation calls to enforce configuration matches:

```bash
python cortex_appsec_repo_config.py --execute
```

### 3. Generate a Baseline Snapshot

If onboarding the sync engine onto an existing workspace with live configurations:

```bash
python cortex_appsec_repo_config.py --export-snapshot
```

This queries the API, formats all active branch and scanner states, and exports them directly into a clean
`snapshot_config.yaml` with secondary scanned branches explicitly mapped (e.g. `scanned_branches: []`).

### 4. Config-less Execution (Global CLI Overrides)

Apply global configurations directly without needing a YAML configuration file. This is highly useful for quick
operational updates via CI/CD pipelines:

```bash
python cortex_appsec_repo_config.py --execute --scan-iac true --primary-branch main --scanned-branches "develop,staging"
```

This dynamically builds the global configuration in-memory and enforces the updates across your active repositories.

---

## 🛠️ Diagnostics & Log Meanings

* **`🛑 Validation failed`** - Your API Key ID, Secret, or URL is invalid. Double check credentials and confirm that your
  key is authorized for AppSec actions.
* **`⚠️ Ignored due to excluded source 'CORTEX_CLI'`** - Skip processing for repositories associated with pipeline or
  command-line integration tools.
* **`⚠️ Limit of 10 branches reached.`** - Your matched configuration resolves to more than 10 tracking branches. The
  engine automatically truncated lowest-priority branches to comply with Cortex API restrictions.
