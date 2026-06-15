"""
================================================================================
Cortex AppSec Branch & Scan Sync - Core Engine (v1.0)
================================================================================
This script synchronizes target branch tracking and AppSec scan configurations
between local declarations (YAML/JSON) and the Palo Alto Cortex platform.
It functions by discovering remote platform states, evaluating rules sequentially
to resolve targets, calculating dry-run differences, and concurrently applying
required configuration updates.
"""

import argparse
import concurrent.futures
import copy
import fnmatch
import hashlib
import json
import logging
import os
import re
import secrets
import string
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import requests
import yaml
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv()

# Setup basic logging format (Level is overridden per instance)
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global defaults for repository exclusion and operational limits
DEFAULT_EXCLUDED_SOURCES = ["CORTEX_CLI", "GITHUB_ACTIONS", "JENKINS"]
DEFAULT_TIMEOUT = 30


# ==============================================================================
# HELPER FUNCTIONS: TRANSLATION, MERGING, AND SANITIZATION
# ==============================================================================

def snake_to_camel(name: str) -> str:
    """
    Translates snake_case to camelCase, honoring Cortex Scanner casing.

    :param name: The snake_case key name to translate.
    :type name: str
    :return: The translated camelCase representation.
    :rtype: str
    """
    if name.lower() in ['iac', 'sca', 'secrets']:
        return name.upper()
    components = name.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])


def camel_to_snake(name: str) -> str:
    """
    Translates camelCase to snake_case, honoring Cortex Scanner casing.

    :param name: The camelCase key name to translate.
    :type name: str
    :return: The translated snake_case representation.
    :rtype: str
    """
    if name.upper() in ['IAC', 'SCA', 'SECRETS']:
        return name.lower()
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def convert_keys(data: Any, converter_func) -> Any:
    """
    Recursively converts dictionary keys using the provided string function.

    :param data: The target dictionary, list, or primitive data to convert.
    :type data: Any
    :param converter_func: The key conversion function to execute.
    :type converter_func: Callable[[str], str]
    :return: The converted data structure with translated keys.
    :rtype: Any
    """
    if isinstance(data, dict):
        return {converter_func(k): convert_keys(v, converter_func) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_keys(i, converter_func) for i in data]
    else:
        return data


def deep_merge(base: dict, update: dict) -> dict:
    """
    Recursively merges the 'update' dictionary into the 'base' dictionary.

    :param base: The target base dictionary.
    :type base: dict
    :param update: The dictionary containing updates to apply.
    :type update: dict
    :return: A newly allocated dictionary representing the merged result.
    :rtype: dict
    """
    merged = base.copy()
    for key, value in update.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def sanitize_scan_config(config: dict) -> dict:
    """
    Safely removes the deprecated 'validateSecrets' key from the scan configuration.

    :param config: The target configuration payload to sanitize.
    :type config: dict
    :return: A reference-safe deep copy of the sanitized configuration.
    :rtype: dict
    """
    if not isinstance(config, dict):
        return config

    # Perform a deep copy to isolate nested references and avoid side-effects
    config_copy = copy.deepcopy(config)
    scanners = config_copy.get("scanners", {})

    if "SECRETS" in scanners:
        scan_opts = scanners["SECRETS"].get("scanOptions", {})
        if "validateSecrets" in scan_opts:
            scan_opts.pop("validateSecrets")

    return config_copy


class CortexAppSecManager:
    """
    Coordinates Application Security settings and target tracking configurations
    for target repositories registered within the Palo Alto Cortex platform.
    """

    def __init__(self, api_key_id: str, api_key_secret: str, api_url: str,
                 auth_type: str = "ADVANCED", config_file: str = "config.yaml",
                 log_level: str = "INFO", save_raw_discovery: bool = False,
                 save_proposed_changes: bool = False, test_mode: bool = False,
                 execute_changes: bool = False, export_snapshot: bool = False,
                 export_snapshot_file: str = "snapshot_config.yaml", max_threads: int = 5,
                 cli_global_overrides: Optional[Dict[str, Any]] = None,
                 exclude_sources: Optional[List[str]] = None,
                 api_timeout: int = DEFAULT_TIMEOUT):
        """
        Initializes the manager, maps configuration, and configures the connection session adapter.

        :param api_key_id: The API Key ID for Cortex platform access.
        :type api_key_id: str
        :param api_key_secret: The API Key Secret for Cortex platform access.
        :type api_key_secret: str
        :param api_url: The Base API URL for the Cortex platform.
        :type api_url: str
        :param auth_type: The authentication protocol to utilize ("STANDARD" or "ADVANCED").
        :type auth_type: str
        :param config_file: The path to the local YAML or JSON configuration file.
        :type config_file: str
        :param log_level: The threshold logging level (e.g., "INFO", "DEBUG").
        :type log_level: str
        :param save_raw_discovery: Flag indicating whether to write the raw repository list to disk.
        :type save_raw_discovery: bool
        :param save_proposed_changes: Flag indicating whether to write calculated differences to disk.
        :type save_proposed_changes: bool
        :param test_mode: Flag indicating whether to truncate processing to a single repository target.
        :type test_mode: bool
        :param execute_changes: Flag enabling mutating API PUT requests (disables dry-run).
        :type execute_changes: bool
        :param export_snapshot: Flag enabling snapshot/backup YAML file export of the active state.
        :type export_snapshot: bool
        :param export_snapshot_file: The path pattern where snapshot outputs are written.
        :type export_snapshot_file: str
        :param max_threads: The maximum size of the thread pool for concurrent updates.
        :type max_threads: int
        :param cli_global_overrides: Dictionary representing target overrides gathered from CLI args.
        :type cli_global_overrides: Optional[Dict[str, Any]]
        :param exclude_sources: List of repository registration sources to bypass during evaluation.
        :type exclude_sources: Optional[List[str]]
        :param api_timeout: The timeout threshold in seconds for all outgoing HTTP requests.
        :type api_timeout: int
        :raises ValueError: If credentials, URLs are missing, or API validation fails.
        """
        self.api_key_id = api_key_id
        self.api_key_secret = api_key_secret
        self.api_url = api_url.rstrip("/")
        self.auth_type = auth_type
        self.config_file = config_file
        self.log_level = log_level
        self.save_raw_discovery = save_raw_discovery
        self.save_proposed_changes = save_proposed_changes
        self.test_mode = test_mode
        self.execute_changes = execute_changes
        self.export_snapshot = export_snapshot
        self.export_snapshot_file = export_snapshot_file
        self.max_threads = max_threads
        self.cli_global_overrides = cli_global_overrides or {}
        self.api_timeout = api_timeout

        # Default to excluding globally defined sources if no list is explicitly provided
        self.exclude_sources = exclude_sources if exclude_sources is not None else DEFAULT_EXCLUDED_SOURCES

        # Set specific logger level for the core engine
        logger.setLevel(getattr(logging, self.log_level, logging.INFO))

        self._validate_env()
        self.session = self._setup_session()

        if not self.validate_api_credentials():
            raise ValueError("Cortex API credentials invalid or API unreachable.")

    @staticmethod
    def _setup_session() -> requests.Session:
        """
        Creates a requests Session configured with connection adapters and retry policies.

        :return: An HTTP session object configured with exponential backoff retries.
        :rtype: requests.Session
        """
        session = requests.Session()
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "PUT", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _validate_env(self) -> None:
        """
        Validates that the essential environment credentials and URLs are non-empty.

        :raises ValueError: If key credentials or target URLs are missing.
        """
        if not self.api_key_id or not self.api_key_secret:
            raise ValueError("Missing required API Key ID or API Secret.")
        if not self.api_url:
            raise ValueError("Missing required API URL.")

    def get_headers(self) -> Dict[str, str]:
        """
        Formulates standard or signature-based security headers for Cortex requests.

        :return: A dictionary of required HTTP headers containing security signatures or tokens.
        :rtype: Dict[str, str]
        """
        if self.auth_type == "STANDARD":
            return {
                "Authorization": self.api_key_secret,
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

        nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
        timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000
        auth_key = f"{self.api_key_secret}{nonce}{timestamp}"
        signature = hashlib.sha256(auth_key.encode("utf-8")).hexdigest()

        return {
            "x-xdr-timestamp": str(timestamp),
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": str(self.api_key_id),
            "Authorization": signature,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    @staticmethod
    def _log_api_error(e: requests.exceptions.RequestException, context: str) -> None:
        """
        Parses and logs request details and raw responses during transaction failures.

        :param e: The captured request exception representing the operational failure.
        :type e: requests.exceptions.RequestException
        :param context: Described functional activity occurring during the error state.
        :type context: str
        """
        error_details = {
            "url": e.request.url if e.request else "N/A",
            "status_code": e.response.status_code if e.response is not None else "N/A",
            "response": e.response.text if e.response is not None else str(e)
        }
        logger.error(f"🛑 {context} failed. Details:\n{json.dumps(error_details, indent=2)}")

    def validate_api_credentials(self) -> bool:
        """
        Verifies credentials against the validation endpoint on the remote platform.

        :return: True if validation succeeds and the API responds with HTTP 200, False otherwise.
        :rtype: bool
        """
        url = f"{self.api_url}/api_keys/validate/"
        logger.info(f"🔄 Validating API credentials at: {url}")
        try:
            response = self.session.post(url, headers=self.get_headers(), json={}, timeout=self.api_timeout)
            if response.status_code != 200:
                logger.error(f"🛑 Validation failed. Status: {response.status_code}. Body: {response.text}")
            response.raise_for_status()
            logger.info("✅ API credentials validated.")
            return True
        except requests.exceptions.RequestException as e:
            self._log_api_error(e, "Validation request")
            return False

    def load_config(self) -> Optional[Dict[str, Any]]:
        """
        Loads, parses, and validates the configuration file from local storage.

        :return: The loaded configuration dictionary if valid, or None if validation fails.
        :rtype: Optional[Dict[str, Any]]
        """
        try:
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    if self.config_file.endswith(('.yaml', '.yml')):
                        config = yaml.safe_load(f) or {}
                    else:
                        config = json.load(f) or {}
            else:
                logger.warning(f"⚠️ Configuration file not found: {self.config_file}. Relying purely on CLI overrides.")

            # Validate structural rules
            overrides = config.get("repo_overrides", [])
            if isinstance(overrides, dict):
                logger.error("🛑 Config Error: 'repo_overrides' must be a List (Array) of rules, not a Dictionary.")
                return None

            for idx, rule in enumerate(overrides):
                if not isinstance(rule, dict) or "org" not in rule or "repo" not in rule:
                    logger.error(f"🛑 Config Error: repo_overrides rule at index {idx} is missing 'org' or 'repo'.")
                    return None

            # Deep Merge the CLI overrides directly into the global_config
            if self.cli_global_overrides:
                current_global = config.get("global_config", {})
                config["global_config"] = deep_merge(current_global, self.cli_global_overrides)
                logger.info("✅ Merged CLI configuration arguments into global_config.")

            return config
        except Exception as e:
            logger.error(f"🛑 Error loading {self.config_file}: {e}")
            return None

    @staticmethod
    def get_matching_rule(owner: str, repo_name: str, overrides: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Resolves and returns the first matching override rule for a given repository.

        :param owner: The organization or owner name of the target repository.
        :type owner: str
        :param repo_name: The name of the target repository.
        :type repo_name: str
        :param overrides: The structured list of rules evaluated top-to-bottom.
        :type overrides: List[Dict[str, Any]]
        :return: The first matching rule dictionary if found, otherwise an empty dictionary.
        :rtype: Dict[str, Any]
        """
        owner_lower = owner.lower()
        repo_lower = repo_name.lower()

        for rule in overrides:
            rule_org = rule.get("org", "").lower()
            rule_repo = rule.get("repo", "").lower()
            allow_wildcard = rule.get("allow_wildcard", False)

            if allow_wildcard:
                if fnmatch.fnmatch(owner_lower, rule_org) and fnmatch.fnmatch(repo_lower, rule_repo):
                    return rule
            else:
                if owner_lower == rule_org and repo_lower == rule_repo:
                    return rule
        return {}

    def get_appsec_repositories(self) -> List[Dict[str, Any]]:
        """
        Queries the Cortex platform to discover all integrated AppSec repositories.

        :return: A list of discovered repository definitions representing remote states.
        :rtype: List[Dict[str, Any]]
        """
        url = f"{self.api_url}/public_api/appsec/v1/repositories"
        try:
            response = self.session.get(url, headers=self.get_headers(), timeout=self.api_timeout)
            response.raise_for_status()
            data = response.json()
            return data.get('reply', data) if isinstance(data, dict) else data
        except requests.exceptions.RequestException as e:
            self._log_api_error(e, "Fetch repositories")
            return []

    def update_branches(self, asset_id: str, selected: List[str], primary: str) -> bool:
        """
        Submits target branches and primary branch settings to the repository branches endpoint.

        :param asset_id: The active registration identifier of the target repository.
        :type asset_id: str
        :param selected: The list of VCS branch names targeted for AppSec scanning.
        :type selected: List[str]
        :param primary: The specific branch name targeted as the primary.
        :type primary: str
        :return: True if the update transaction succeeds, False otherwise.
        :rtype: bool
        """
        url = f"{self.api_url}/public_api/appsec/v1/repositories/{asset_id}/branches"
        payload = {"selectedBranches": selected, "primaryBranch": primary}
        try:
            response = self.session.put(url, headers=self.get_headers(), json=payload, timeout=self.api_timeout)
            response.raise_for_status()
            logger.info(f"✅ Successfully updated branches for Asset ID: {asset_id}")
            return True
        except requests.exceptions.RequestException as e:
            self._log_api_error(e, f"Update Branches (Asset {asset_id})")
            return False

    def update_scan_configuration(self, asset_id: str, payload: Dict[str, Any]) -> bool:
        """
        Submits the deep-merged scanner specifications to the scan configuration endpoint.

        :param asset_id: The active registration identifier of the target repository.
        :type asset_id: str
        :param payload: The target camelCase configuration payload representing desired scanner states.
        :type payload: Dict[str, Any]
        :return: True if the configuration update transaction succeeds, False otherwise.
        :rtype: bool
        """
        url = f"{self.api_url}/public_api/appsec/v1/repositories/{asset_id}/scan-configuration"
        try:
            response = self.session.put(url, headers=self.get_headers(), json=payload, timeout=self.api_timeout)
            response.raise_for_status()
            logger.info(f"✅ Successfully updated scan configuration for Asset ID: {asset_id}")
            return True
        except requests.exceptions.RequestException as e:
            self._log_api_error(e, f"Update Scan Config (Asset {asset_id})")
            return False

    def generate_snapshot_config(self, repos: List[Dict[str, Any]]) -> None:
        """
        Translates the active remote state into a structured declarative local backup.

        :param repos: The list of raw repository definitions discovered from the platform.
        :type repos: List[Dict[str, Any]]
        """
        snapshot = {"global_config": {}, "repo_overrides": []}

        for repo in repos:
            repo_name = repo.get("name")
            owner = repo.get("owner")
            asset_id = repo.get("id")
            source = repo.get("source", "UNKNOWN")

            if not asset_id or not repo_name or not owner:
                continue

            # Skip repositories that match an excluded source
            if source in self.exclude_sources:
                continue

            # Scan Config Extraction & Translation
            raw_scan_config = repo.get("scanConfiguration", {})
            sanitized_raw_config = sanitize_scan_config(raw_scan_config)
            snake_scan_config = convert_keys(sanitized_raw_config, camel_to_snake)

            repo_config = {"org": owner, "repo": repo_name}

            # Branch Extraction (Only write branch configurations if tracking is active)
            scanned_branches = repo.get("scannedBranches", [])
            if scanned_branches:
                current_tracked = [b.get('name') for b in scanned_branches if b.get('name')]
                current_primary = next((b.get('name') for b in scanned_branches if b.get('isPrimary')),
                                       repo.get("defaultBranch"))
                additional_branches = [b for b in current_tracked if b != current_primary]

                if current_primary:
                    repo_config["primary_branch"] = current_primary

                # Always track scanned_branches (even if empty) to represent the exact tracked state
                repo_config["scanned_branches"] = additional_branches

            if snake_scan_config:
                repo_config["scan_config"] = snake_scan_config

            snapshot["repo_overrides"].append(repo_config)

        try:
            with open(self.export_snapshot_file, 'w') as f:
                yaml.dump(snapshot, f, default_flow_style=False, sort_keys=False)
            logger.info(f"✅ Successfully generated snapshot configuration to '{self.export_snapshot_file}'.")
        except Exception as e:
            logger.error(f"🛑 Failed to generate snapshot config: {e}")

    def run(self) -> None:
        """
        Runs the end-to-end configuration reconciliation and synchronization loop.
        """
        # --- 1. Bootstrapping & Discovery Phase ---
        config = self.load_config()
        if config is None:
            logger.error("🛑 Halting execution due to configuration validation failure.")
            return

        global_config = config.get("global_config", {})
        repo_overrides = config.get("repo_overrides", [])

        has_actionable_config = bool(global_config or repo_overrides)
        if not has_actionable_config:
            logger.warning("⚠️ No actionable configuration provided. Updates disabled.")

        repos = self.get_appsec_repositories()
        if not repos:
            logger.warning("⚠️ No repositories identified for processing.")
            return

        if self.export_snapshot:
            self.generate_snapshot_config(repos)
            logger.info("✅ Snapshot generation complete.")

        if self.save_raw_discovery:
            with open("raw_discovery_repositories.json", "w") as f:
                json.dump(repos, f, indent=2)
            logger.info("✅ Saved raw discovery repositories to 'raw_discovery_repositories.json'.")

        # Halt execution if no actionable configuration is provided to prevent unintended mutations.
        if not has_actionable_config:
            return

        proposed_changes = []

        # --- 2. Evaluation & Delta Tracking Phase ---
        for repo in repos:
            asset_id = repo.get("id")
            repo_name = repo.get("name")
            owner = repo.get("owner")
            source = repo.get("source", "UNKNOWN")

            if not asset_id or not repo_name or not owner:
                continue

            repo_id_str = f"{owner}/{repo_name}"

            # Skip repositories that match an excluded source
            if source in self.exclude_sources:
                logger.debug(f"⚠️ {repo_id_str}: Ignored due to excluded source '{source}'.")
                continue

            matched_rule = self.get_matching_rule(owner, repo_name, repo_overrides)
            if matched_rule.get("ignore", False):
                continue

            exclude_global = matched_rule.get("exclude_global", False)

            # --- BRANCH EVALUATION ---
            scanned_branches = repo.get("scannedBranches", [])
            current_tracked = {b.get('name') for b in scanned_branches if b.get('name')}
            current_primary = next((b.get('name') for b in scanned_branches if b.get('isPrimary')),
                                   repo.get("defaultBranch"))

            rule_primary = matched_rule.get("primary_branch")
            global_primary = global_config.get("primary_branch") if not exclude_global else None
            target_primary = rule_primary or global_primary or current_primary

            target_selected_list = [target_primary]

            # Safe Branch Inheritance: Determine if branches were explicitly configured
            explicit_branches = False
            potential_extras = []

            if "scanned_branches" in matched_rule:
                potential_extras += matched_rule["scanned_branches"] or []
                explicit_branches = True

            if not exclude_global and "scanned_branches" in global_config:
                potential_extras += global_config["scanned_branches"] or []
                explicit_branches = True

            if explicit_branches:
                for branch in potential_extras:
                    if branch not in target_selected_list:
                        target_selected_list.append(branch)
            else:
                # Inherit existing tracked branches if no branches were explicitly targeted
                # (Prevents accidental wipeouts when users only update scan_config)
                for branch in current_tracked:
                    if branch not in target_selected_list:
                        target_selected_list.append(branch)

            if len(target_selected_list) > 10:
                target_selected_list = target_selected_list[:10]
                logger.warning(f"⚠️ {repo_id_str}: Limit of 10 branches reached. Excess truncated.")

            target_selected_set = set(target_selected_list)

            branch_drift = (target_primary != current_primary) or (target_selected_set != current_tracked)

            # --- SCAN CONFIGURATION EVALUATION ---
            current_scan_config = sanitize_scan_config(repo.get("scanConfiguration", {}))

            global_scan_config = global_config.get("scan_config", {}) if not exclude_global else {}
            rule_scan_config = matched_rule.get("scan_config", {})

            # Deep Merge: Rule overrides Global
            target_scan_config_snake = deep_merge(global_scan_config, rule_scan_config)

            # Translate Target to camelCase and sanitize
            target_scan_config_camel = convert_keys(target_scan_config_snake, snake_to_camel)
            target_scan_config_camel = sanitize_scan_config(target_scan_config_camel)

            # We only evaluate drift if there is an explicit target scan config requested
            scan_drift = False
            if target_scan_config_camel and (current_scan_config != target_scan_config_camel):
                scan_drift = True

            # --- PROPOSAL APPENDING ---
            if not branch_drift and not scan_drift:
                logger.debug(f"✅ {repo_id_str}: No changes required.")
                continue

            logger.info(f"🔄 {repo_id_str}: Delta detected (Branch Drift: {branch_drift} | Scan Drift: {scan_drift})")

            proposed_changes.append({
                "asset_id": asset_id,
                "repo_name": repo_id_str,
                "source": source,
                "branch_update": {
                    "required": branch_drift,
                    "current_state": {"primary": current_primary, "tracked": list(current_tracked)},
                    "target_state": {"primaryBranch": target_primary, "selectedBranches": target_selected_list}
                },
                "scan_config_update": {
                    "required": scan_drift,
                    "current_state": current_scan_config,
                    "target_state": target_scan_config_camel
                }
            })

        if self.save_proposed_changes:
            with open("proposed_changes.json", "w") as f:
                json.dump(proposed_changes, f, indent=2)
            logger.info("✅ Saved proposed changes to 'proposed_changes.json'.")

        # --- 3. Pre-Execution Validation ---
        logger.info(
            f"✅ Pre-Execution Summary: Evaluated {len(repos)} repositories. Found {len(proposed_changes)} repositories requiring updates.")

        if not self.execute_changes:
            logger.info("✅ Discovery complete. EXECUTE_CHANGES is false. Halting before API mutations.")
            return

        if not proposed_changes:
            logger.info("✅ No updates required.")
            return

        # --- 4. Execution Phase (Multithreaded) ---
        to_execute = proposed_changes[:1] if self.test_mode else proposed_changes
        if self.test_mode:
            logger.warning("⚠️ TEST_MODE active: Only the first proposed change will be applied.")

        logger.info(f"🔄 Starting multi-threaded execution with {self.max_threads} workers...")
        successful_updates = 0
        failed_updates = 0

        def process_update(change: Dict[str, Any]) -> bool:
            """Independent API execution router."""
            success = True
            if change.get('branch_update', {}).get('required'):
                branch_success = self.update_branches(
                    change['asset_id'],
                    change['branch_update']['target_state']['selectedBranches'],
                    change['branch_update']['target_state']['primaryBranch']
                )
                success = success and branch_success

            if change.get('scan_config_update', {}).get('required'):
                scan_success = self.update_scan_configuration(
                    change['asset_id'],
                    change['scan_config_update']['target_state']
                )
                success = success and scan_success

            return success

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_repo = {executor.submit(process_update, change): change['repo_name'] for change in to_execute}
            for future in concurrent.futures.as_completed(future_to_repo):
                repo_id_str = future_to_repo[future]
                try:
                    if future.result():
                        successful_updates += 1
                    else:
                        failed_updates += 1
                except Exception as exc:
                    logger.error(f"🛑 {repo_id_str} generated an unexpected exception: {exc}")
                    failed_updates += 1

        logger.info(
            f"✅ Final Execution Summary: Evaluated {len(repos)} total repos. Applied updates to {len(to_execute)} repos. ({successful_updates} Succeeded, {failed_updates} Failed).")


# ==============================================================================
# LOCAL STANDALONE EXECUTION ENTRYPOINT (ADVANCED CLI)
# ==============================================================================

def str2bool(v):
    if isinstance(v, bool): return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


if __name__ == "__main__":
    try:
        # --- CLI Parsing (Highest Precedence) ---
        parser = argparse.ArgumentParser(description="Cortex AppSec Branch & Scan Sync (v1.0)")

        parser.add_argument('--execute', action='store_true', help='Execute changes (turns off RO default)')
        parser.add_argument('--config', default=os.getenv("SCAN_CONFIG_FILE", "config.yaml"),
                            help='Path to YAML config file')
        parser.add_argument('--api-id', default=os.getenv("CORTEX_API_ID"), help='Cortex API Key ID')
        parser.add_argument('--api-secret', default=os.getenv("CORTEX_API_SECRET"), help='Cortex API Key Secret')
        parser.add_argument('--api-url', default=os.getenv("CORTEX_API_URL"),
                            help='Cortex API URL (e.g., https://api-tenant.paloaltonetworks.com)')
        parser.add_argument('--log-level', default=os.getenv("LOG_LEVEL", "INFO").upper(), help='Log Level')
        parser.add_argument('--export-snapshot', action='store_true', help='Export snapshot baseline')
        parser.add_argument('--test-mode', action='store_true', help='Truncate updates to 1 item')
        parser.add_argument('--exclude-sources',
                            default=os.getenv("EXCLUDE_SOURCES", ",".join(DEFAULT_EXCLUDED_SOURCES)),
                            help=f'Comma-separated list of repository sources to ignore (default: {",".join(DEFAULT_EXCLUDED_SOURCES)})')
        parser.add_argument('--api-timeout', type=int,
                            default=int(os.getenv("CORTEX_API_TIMEOUT", str(DEFAULT_TIMEOUT))),
                            help='API request timeout threshold in seconds')

        # Config-less execution flags (Global Overrides)
        parser.add_argument('--primary-branch', help='Sets the global primary branch')
        parser.add_argument('--scanned-branches', help='Comma-separated list of global branches')
        parser.add_argument('--excluded-paths', help='Comma-separated list of paths to exclude')
        parser.add_argument('--scan-iac', type=str2bool, help='Enable/Disable IAC scanner')
        parser.add_argument('--scan-sca', type=str2bool, help='Enable/Disable SCA scanner')
        parser.add_argument('--scan-secrets', type=str2bool, help='Enable/Disable Secrets scanner')
        parser.add_argument('--pr-scanning', type=str2bool, help='Enable/Disable PR scanning')
        parser.add_argument('--pr-block-on-error', type=str2bool, help='Enable/Disable blocking on PR error')
        parser.add_argument('--tag-module-blocks', type=str2bool, help='Enable/Disable tagging module blocks')
        parser.add_argument('--tag-resource-blocks', type=str2bool, help='Enable/Disable tagging resource blocks')
        parser.add_argument('--secret-validation', type=str2bool, help='Enable/Disable secret validation')
        parser.add_argument('--secret-git-history', type=str2bool, help='Enable/Disable git history scanning')

        args = parser.parse_args()

        # Merge Execution/Toggles (CLI Overrides Environment Variables)
        execute_changes = args.execute or (os.getenv("EXECUTE_CHANGES", "false").lower() == "true")
        export_snapshot = args.export_snapshot or (os.getenv("EXPORT_SNAPSHOT", "false").lower() == "true")
        test_mode = args.test_mode or (os.getenv("TEST_MODE", "false").lower() == "true")

        # Parse exclude_sources into a list
        exclude_sources_list = [s.strip() for s in args.exclude_sources.split(',')] if args.exclude_sources else []

        # --- Dynamic Config-Less Dictionary Builder ---
        cli_overrides = {
            "scan_config": {
                "scanners": {
                    "iac": {},
                    "sca": {},
                    "secrets": {
                        "scan_options": {}
                    }
                },
                "pr_scanning": {},
                "tagging_bot": {}
            }
        }

        if args.primary_branch is not None:
            cli_overrides["primary_branch"] = args.primary_branch
        if args.scanned_branches is not None:
            cli_overrides["scanned_branches"] = [b.strip() for b in args.scanned_branches.split(',')]
        if args.excluded_paths is not None:
            cli_overrides["scan_config"]["excluded_paths"] = [p.strip() for p in args.excluded_paths.split(',')]

        if args.scan_iac is not None:
            cli_overrides["scan_config"]["scanners"]["iac"]["is_enabled"] = args.scan_iac
        if args.scan_sca is not None:
            cli_overrides["scan_config"]["scanners"]["sca"]["is_enabled"] = args.scan_sca
        if args.scan_secrets is not None:
            cli_overrides["scan_config"]["scanners"]["secrets"]["is_enabled"] = args.scan_secrets

        if args.pr_scanning is not None:
            cli_overrides["scan_config"]["pr_scanning"]["is_enabled"] = args.pr_scanning
        if args.pr_block_on_error is not None:
            cli_overrides["scan_config"]["pr_scanning"]["block_on_error"] = args.pr_block_on_error

        if args.tag_module_blocks is not None:
            cli_overrides["scan_config"]["tagging_bot"]["tag_module_blocks"] = args.tag_module_blocks
        if args.tag_resource_blocks is not None:
            cli_overrides["scan_config"]["tagging_bot"]["tag_resource_blocks"] = args.tag_resource_blocks

        if args.secret_validation is not None:
            cli_overrides["scan_config"]["scanners"]["secrets"]["scan_options"][
                "secret_validation"] = args.secret_validation
        if args.secret_git_history is not None:
            cli_overrides["scan_config"]["scanners"]["secrets"]["scan_options"]["git_history"] = args.secret_git_history


        # Prune empty dictionaries out of the nested CLI overrides payload
        def prune_empty_dicts(d):
            if not isinstance(d, dict): return d
            pruned = {k: prune_empty_dicts(v) for k, v in d.items()}
            return {k: v for k, v in pruned.items() if v != {}}


        clean_cli_overrides = prune_empty_dicts(cli_overrides)

        # Evaluate the snapshot name formatting for local execution
        snapshot_template = os.getenv("EXPORT_SNAPSHOT_FILE", "snapshot_config.yaml")
        evaluated_snapshot_name = datetime.now().strftime(snapshot_template)

        # Initialize the Manager
        manager = CortexAppSecManager(
            api_key_id=args.api_id,
            api_key_secret=args.api_secret,
            api_url=args.api_url or "",
            auth_type=os.getenv("CORTEX_API_TYPE", "ADVANCED").upper(),
            config_file=args.config,
            log_level=args.log_level,
            save_raw_discovery=os.getenv("SAVE_RAW_DISCOVERY", "false").lower() == "true",
            save_proposed_changes=os.getenv("SAVE_PROPOSED_CHANGES", "false").lower() == "true",
            test_mode=test_mode,
            execute_changes=execute_changes,
            export_snapshot=export_snapshot,
            export_snapshot_file=evaluated_snapshot_name,
            max_threads=int(os.getenv("MAX_THREADS", "5")),
            cli_global_overrides=clean_cli_overrides,
            exclude_sources=exclude_sources_list,
            api_timeout=args.api_timeout
        )
        manager.run()
    except Exception as error:
        logger.error(f"🛑 Standalone Execution Failed: {error}")
        exit(1)
