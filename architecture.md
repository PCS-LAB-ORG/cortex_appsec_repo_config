# Cortex AppSec Repository Configuration Engine: Architecture & Design (v1.0)

## 1. System Overview

The `cortex_appsec_repo_config.py` engine is a highly deterministic, multithreaded synchronization system. It aligns the
Cortex AppSec platform's branch scanning and scanner security configurations (IaC, SCA, Secrets) with a user-defined
GitOps model (supporting YAML or JSON). It is designed to handle large-scale, complex enterprise VCS environments safely
and efficiently.

## 2. Comprehensive Core Engine Workflow

The engine runs on a cyclic reconciliation sequence, transitioning the remote API state into your local GitOps
definitions.

```text
      [ 1. Bootstrap ] ──► Reads local configuration & environment variable variables
              │
              ▼
    [ 2. Authenticate ] ──► POST /api_keys/validate/ with cryptographic SHA-256 signature
              │
              ▼
    [ 3. Backup State ] ──► (If enabled) Writes snapshot_config.yaml (snake_case) & raw json
              │
              ▼
    [ 4. Rule Matching ] ──► Sequential (First-Match-Wins) top-to-bottom rule resolution
              │
              ▼
   [ 5. Compile Target ] ──► Builds Branch Lists (enforcing "1+9 Limit") & deep-merges scan trees
              │
              ▼
    [ 6. Drift Tracking ] ──► Calculates separate Branch Drift and Scan Config Drift
              │
              ▼
     [ 7. Thread Queue ] ──► Concurrent PUT dispatchers handle mutations in parallel
```

## 3. The "First-Match-Wins" Configuration Logic

The core of the architecture relies on an ordered list (`repo_overrides`) evaluated strictly top-to-bottom.

### 3.1 Resolution Hierarchy

For every repository discovered in Cortex, the target state is resolved using the following priority:

1. **Repository Overrides**: The script evaluates the `repo_overrides` list. The *first* configuration block that
   matches the repository's `org` and `repo` name is applied. All subsequent configurations for that repo are ignored.
2. **Global Configuration**: If no override configuration matches the repository, it falls back entirely to the
   `global_config` block.
3. **Existing State**: If no overrides or global defaults dictate the Primary Branch or Scanned Branches, the engine
   safely preserves the repository's existing state from Cortex.

## 4. Configuration Flags & Determinism

To ensure predictable state tracking, every configuration block requires strict explicit string definitions.

### 4.1 Strict Schema Requirements

Every configuration block inside `repo_overrides` MUST explicitly declare both an `org` and a `repo` string. The script
forces case-insensitive matching across the board to prevent YAML casing errors.

### 4.2 Boolean Modifiers (Defaults to False)

Configuration blocks support three powerful boolean modifiers to shape execution. If omitted from the YAML, these
default to `false`.

- **`allow_wildcard` (Default: false)**: Opt-in flag that allows Python `fnmatch` wildcards (`*`) in the `org` or `repo`
  strings, turning a single configuration into a bulk-applicator.
- **`ignore` (Default: false)**: Immediately halts processing for the matched repository. No branch evaluation occurs,
  and no API calls will be proposed or executed.
- **`exclude_global` (Default: false)**: Severs the repository from the global configuration. The engine will ONLY apply
  the branches and scan configurations explicitly defined in the local block and will ignore the `global_config`
  entirely.

## 5. AppSec Scanner Configuration Engine (v1.0)

Managing nested security settings requires specialized handling to prevent accidental overwrites.

### 5.1 Dictionary Deep Merging Strategy

AppSec specifications (PR Scanning, Tagging Bots, Scanner toggles) are represented as nested JSON objects. A flat
dictionary update would completely overwrite sibling keys when modifying a single child node.

- **Mechanism**: The `deep_merge` algorithm recursively walks nested dictionary nodes.
- **Behavior**: Local repository rules can selectively override specific properties (e.g., setting
  `scanners.secrets.scan_options.git_history: false`) while safely preserving the remainder of the inherited global
  settings.

### 5.2 Bi-Directional Case Translation Layer

Cortex API schemas expect `camelCase` and ACRONYMS (e.g., `scanners.IAC`, `prScanning.blockOnError`), causing stylistic
friction against standard Pythonic configurations.

- **Forward (Reconciliation)**: Local configuration is authored in clean `snake_case`. The translation layer recursively
  maps these to `camelCase` and capitalizes scanner acronyms before submitting PUT payloads.
- **Reverse (Snapshots)**: Active remote states fetched from the API in `camelCase` are translated recursively back into
  `snake_case` before outputting snapshot backups.

### 5.3 "validateSecrets" Sanitization Block

A platform quirk in the Cortex API returns a legacy boolean `validateSecrets` inside the `SECRETS` block during GET
queries but immediately rejects PUT submissions containing this key with an HTTP 400 Bad Request. The
`sanitize_scan_config()` method uses a side-effect-free deep copy (`copy.deepcopy()`) to safely pop out the
`validateSecrets` key, preventing false-positive drift detection and API validation rejections.

## 6. Branch Limit & Priority Logic

Cortex AppSec maintains a hard limit of 10 scanned branches per repository. The architecture manages this limit
internally before making API calls.

### 6.1 The 1+9 Rule

The resolution engine enforces a "1 Primary + 9 Scanned" rule:

- **Priority 1: Target Primary**: The resolved Primary Branch is ALWAYS the first item in the list.
- **Priority 2: Override Scanned Branches**: Branches explicitly listed in the matched override configuration are added
  next.
- **Priority 3: Global Scanned Branches**: General naming conventions (e.g., develop, staging) are added until the
  10-item limit is reached (unless `exclude_global` is true).

### 6.2 Safe Inheritance vs. Explicit Branch Isolation

To navigate the risk of empty branch declarations accidentally triggering bulk branch deletions, the branch resolver
splits tracking into two distinct logic paths:

- **Safe Branch Inheritance (Default Omission)**: If `scanned_branches` is completely omitted from a matched rule (i.e.,
  the user only wants to update scan settings), the engine dynamically reads the currently tracked branches from the
  Cortex API and inherits them into the payload target, preventing accidental untracking.
- **Explicit Branch Isolation (Empty Array `[]`)**: If a user explicitly sets `scanned_branches: []` (as done by the
  snapshot engine), the engine recognizes this as an active command to disable secondary branch tracking, untracking
  everything except the resolved primary.

## 7. Primary Branch Integrity

The architecture enforces strict integrity for the primary branch:

- **Mandatory Inclusion**: The `primaryBranch` MUST be included in the `selectedBranches` array payload. The script
  handles this automatically.
- **Old Primary Removal**: If the Primary Branch is changed via configuration, the previous primary is automatically
  removed from tracking UNLESS it is explicitly listed in your target `scanned_branches`.

## 8. Lifecycle, Safety & Efficiency

The script follows a strictly idempotent "Discovery-First" lifecycle to minimize API footprint and prevent unintended
mutations:

1. **Halt-on-Empty Guard**: If the loaded configuration has no actionable rules (all commented out or empty), the script
   cleanly exits before Delta Tracking to prevent misinterpreting the empty file as a bulk-delete command.
2. **Bulk Discovery**: Fetches raw repository states and AppSec configurations via a single bulk GET request.
3. **Snapshot Generation**: If `EXPORT_SNAPSHOT=true`, the engine utilizes the discovered state to generate a baseline
   configuration file, forcing `scanned_branches: []` where appropriate to lock in the exact state.
4. **Dual Delta Tracking**: The engine calculates drift independently for branches and scan configurations. A drift in
   one does not force an unnecessary API call for the other.
5. **Proposal**: Generates a `proposed_changes.json` containing only the identified configuration drift.
6. **Execution (Multithreaded)**: Mutates state via PUT requests ONLY if `EXECUTE_CHANGES=true`.
    - **Concurrency**: Uses a `ThreadPoolExecutor` (controlled by `MAX_THREADS`, default 5) to execute endpoint updates
      rapidly in parallel.
    - **TEST_MODE**: If enabled, truncates the execution queue to the very first item, allowing for safe end-to-end
      integration testing.
    - **Fault Tolerance**: Network failures or HTTP 429 Rate Limits are managed via automatic exponential backoff
      retries.

## 9. Authentication & API Endpoints

- **Advanced Auth**: Uses SHA256 signatures with nonce/timestamp (`CORTEX_API_TYPE=ADVANCED`).
- **Endpoints Utilized**:
    - `POST /api_keys/validate/` (Credential verification)
    - `GET /public_api/appsec/v1/repositories` (Bulk Discovery)
    - `PUT /public_api/appsec/v1/repositories/{assetId}/branches` (Branch sync payload)
    - `PUT /public_api/appsec/v1/repositories/{assetId}/scan-configuration` (AppSec scan sync payload)
