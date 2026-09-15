"""Container Sandbox Escape Analysis for ReconPro v8.0.

Analyzes Docker and Kubernetes configurations for container escape vectors.
Deep inspection of Dockerfiles, K8s manifests, and compound escape patterns.

Zero external dependencies — stdlib only (re, json, pathlib, os).
For YAML: attempts ``import yaml``, falls back to simple line parser.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import Finding


# ── Severity / score helpers ─────────────────────────────────────────

_SEV_WEIGHT: Dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 1.0,
}

_PTS_MAP: Dict[str, int] = {
    "critical": 15,
    "high": 10,
    "medium": 6,
    "low": 3,
    "info": 1,
}


def _dread(severity: str) -> float:
    return _SEV_WEIGHT.get(severity.lower(), 2.5)


def _pts(severity: str) -> int:
    return _PTS_MAP.get(severity.lower(), 3)


def _ev(file: str, line: int) -> str:
    return f"{file}:{line}"


def _read_file(path: str, max_size: int = 1048576) -> str:
    """Read file contents safely."""
    try:
        size = os.path.getsize(path)
        if size > max_size:
            return "[file too large]"
        with open(path, errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _simple_yaml_parse(text: str) -> Any:
    """Fallback YAML parser when PyYAML is not installed."""
    try:
        import yaml  # type: ignore[import-untyped]
        return yaml.safe_load(text)
    except Exception:
        pass
    try:
        return json.loads(text)
    except Exception:
        pass
    result: Dict[str, Any] = {}
    current_list_key: Optional[str] = None
    list_items: List[Dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        list_match = re.match(r"^\s*-\s+(\w+):\s*(.*)$", line)
        if list_match:
            key, val = list_match.group(1), list_match.group(2).strip()
            if key != current_list_key:
                if current_list_key is not None and list_items:
                    result[current_list_key] = list_items
                current_list_key = key
                list_items = []
            item: Dict[str, Any] = {key: val}
            list_items.append(item)
            continue
        kv_match = re.match(r"^([\w.]+):\s*(.*)$", stripped)
        if kv_match:
            key, val = kv_match.group(1), kv_match.group(2).strip()
            if current_list_key is not None:
                pass
            if val.lower() in ("true", "false", "null"):
                result[key] = {"true": True, "false": False, "null": None}[val.lower()]
            else:
                try:
                    result[key] = json.loads(val)
                except Exception:
                    result[key] = val
    if current_list_key is not None and list_items:
        result[current_list_key] = list_items
    return result


def _yaml_load_all(text: str) -> List[Any]:
    """Load all YAML documents from text."""
    try:
        import yaml  # type: ignore[import-untyped]
        return list(yaml.safe_load_all(text)) or []
    except Exception:
        pass
    docs: List[Any] = [_simple_yaml_parse(text)]
    return docs


def _dict_get(data: Any, *keys: str, default: Any = None) -> Any:
    """Deep get from nested dicts, safe against missing keys."""
    current = data
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k, default)
        else:
            return default
    return current


def _search_dicts(data: Any, key: str) -> List[Any]:
    """Recursively find all values for a given key in nested structures."""
    results: List[Any] = []
    if isinstance(data, dict):
        if key in data:
            results.append(data[key])
        for v in data.values():
            results.extend(_search_dicts(v, key))
    elif isinstance(data, list):
        for item in data:
            results.extend(_search_dicts(item, key))
    return results


def _has_value_in_structure(data: Any, key: str, target_value: Any) -> bool:
    """Check if any occurrence of key has the target value."""
    values = _search_dicts(data, key)
    return target_value in values


def _get_key_values(data: Any, key: str) -> List[Any]:
    """Get all values for a key, flattening lists."""
    flat: List[Any] = []
    for v in _search_dicts(data, key):
        if isinstance(v, list):
            flat.extend(v)
        else:
            flat.append(v)
    return flat


def _find_container_specs(data: Any) -> List[Dict[str, Any]]:
    """Find all container spec dicts in a K8s manifest."""
    specs: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        spec = data.get("spec")
        if isinstance(spec, dict):
            for ck in ("containers", "initContainers"):
                containers = spec.get(ck)
                if isinstance(containers, list):
                    specs.extend(containers)
            template = spec.get("template")
            if isinstance(template, dict):
                tmpl_spec = template.get("spec")
                if isinstance(tmpl_spec, dict):
                    for ck in ("containers", "initContainers"):
                        containers = tmpl_spec.get(ck)
                        if isinstance(containers, list):
                            specs.extend(containers)
    return specs


def _find_pod_or_template_spec(data: Any) -> Optional[Dict[str, Any]]:
    """Find the pod-level spec (or template spec for Deployments)."""
    if isinstance(data, dict):
        spec = data.get("spec")
        if isinstance(spec, dict):
            template = spec.get("template")
            if isinstance(template, dict):
                tmpl_spec = template.get("spec")
                if isinstance(tmpl_spec, dict):
                    return tmpl_spec
            return spec
    return None


# ══════════════════════════════════════════════════════════════════════
#  DockerfileAnalyzer
# ══════════════════════════════════════════════════════════════════════

class DockerfileAnalyzer:
    """Analyzes Dockerfiles for security misconfigurations and escape vectors."""

    SENSITIVE_PATHS = re.compile(
        r"\.(env|aws|ssh)|id_rsa|.*\.pem|credentials",
        re.IGNORECASE,
    )
    SECRET_ENV_PATTERN = re.compile(
        r"(?i)ENV\s+.*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)",
    )
    DANGEROUS_PORTS = {22, 2375, 2376, 6379, 27017, 5432, 3306}

    def analyze(self, path: str) -> List[Dict[str, Any]]:
        """Analyze a Dockerfile and return a list of finding dicts."""
        findings: List[Dict[str, Any]] = []
        content = _read_file(path)
        if not content or content.startswith("[file too large]"):
            return findings

        lines = content.splitlines()
        fname = os.path.basename(path)
        has_user = False
        had_nonroot_user = False
        has_healthcheck = False
        has_from = False
        from_lines: List[int] = []
        secret_env_in_builder = False

        # Check 1: No .dockerignore found
        dockerignore_path = os.path.join(os.path.dirname(path), ".dockerignore")
        if not os.path.exists(dockerignore_path):
            findings.append({
                "title": "No .dockerignore Found",
                "severity": "low",
                "category": "docker_build",
                "description": "No .dockerignore file found alongside Dockerfile. Unnecessary files may be included in the build context.",
                "evidence": f"{fname}: missing .dockerignore",
                "remediation": "Create a .dockerignore file to exclude .git, .env, node_modules, and other unnecessary files from the build context.",
                "line_number": 0,
            })

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            directive_match = re.match(r"^(?:FROM|RUN|COPY|ADD|ENV|EXPOSE|USER|HEALTHCHECK|ARG|ENTRYPOINT|CMD)\b", stripped, re.IGNORECASE)

            # Check 2: FROM without tag or :latest
            if re.match(r"^FROM\b", stripped, re.IGNORECASE):
                has_from = True
                from_lines.append(idx)
                from_part = stripped[4:].strip()
                if from_part.startswith("--platform="):
                    from_part = re.sub(r"^--platform=\S+\s+", "", from_part)
                if re.match(r"^AS\b", from_part, re.IGNORECASE):
                    from_part = re.sub(r"^AS\s+\S+\s*", "", from_part, flags=re.IGNORECASE)
                if ":" not in from_part:
                    findings.append({
                        "title": f"FROM Without Tag: {from_part}",
                        "severity": "medium",
                        "category": "docker_build",
                        "description": f"Base image '{from_part}' has no explicit tag. Defaults to ':latest' which is non-reproducible.",
                        "evidence": _ev(fname, idx),
                        "remediation": f"Pin the base image to a specific digest: FROM {from_part}:<tag>@<digest>",
                        "line_number": idx,
                    })
                elif from_part.endswith(":latest"):
                    findings.append({
                        "title": f"FROM Uses :latest Tag: {from_part}",
                        "severity": "medium",
                        "category": "docker_build",
                        "description": f"Base image '{from_part}' uses the ':latest' tag. Builds are non-reproducible and may break unexpectedly.",
                        "evidence": _ev(fname, idx),
                        "remediation": f"Pin to a specific version and digest: FROM {from_part.split(':')[0]}:<version>@<digest>",
                        "line_number": idx,
                    })

            # Check 3: COPY/ADD of sensitive paths
            copy_match = re.match(r"^(?:COPY|ADD)\s+(.+?)(?:\s+(?:/|\S+))?$", stripped, re.IGNORECASE)
            if copy_match:
                src_part = copy_match.group(1).strip()
                # Remove flags like --chown=, --from=
                src_part = re.sub(r"^--\w+[=\s]+\S+\s+", "", src_part)
                # Could be multi-source: "src1 src2  dest"
                src_parts = src_part.split()
                for sp in src_parts:
                    if self.SENSITIVE_PATHS.search(sp):
                        findings.append({
                            "title": f"Sensitive Path in COPY/ADD: {sp}",
                            "severity": "critical",
                            "category": "docker_secret_leak",
                            "description": f"Sensitive file '{sp}' is being copied into the container image. This may expose secrets, SSH keys, or cloud credentials.",
                            "evidence": _ev(fname, idx),
                            "remediation": f"Avoid copying '{sp}' into the image. Use multi-stage builds, Docker secrets, or runtime volume mounts instead.",
                            "line_number": idx,
                        })

            # Check 4: ADD of remote URL (supply chain risk)
            add_match = re.match(r"^ADD\s+(https?://\S+)", stripped, re.IGNORECASE)
            if add_match:
                url = add_match.group(1).split()[0]
                findings.append({
                    "title": f"ADD Remote URL (Supply Chain Risk): {url[:60]}",
                    "severity": "medium",
                    "category": "docker_supply_chain",
                    "description": f"ADD fetches from a remote URL. The remote content could change, introducing malicious files.",
                    "evidence": _ev(fname, idx),
                    "remediation": "Use COPY with a locally-verified file, or use RUN curl/wget with integrity verification (checksums, GPG).",
                    "line_number": idx,
                })

            # Check 5: ENV with secret patterns
            if self.SECRET_ENV_PATTERN.search(stripped):
                env_match = re.match(r"^ENV\s+(\S+?)=(.*)$", stripped, re.IGNORECASE)
                if env_match:
                    var_name = env_match.group(1)
                    var_val = env_match.group(2).strip().strip('"').strip("'")
                    if var_val and not var_val.startswith("$"):
                        findings.append({
                            "title": f"Secret in ENV Variable: {var_name}",
                            "severity": "high",
                            "category": "docker_secret_leak",
                            "description": f"Environment variable '{var_name}' appears to contain a hardcoded secret. This is baked into the image and visible in 'docker inspect'.",
                            "evidence": _ev(fname, idx),
                            "remediation": f"Use Docker secrets, a secret management system (Vault, AWS Secrets Manager), or pass secrets at runtime via -e or --env-file.",
                            "line_number": idx,
                        })
                        if len(from_lines) > 1:
                            secret_env_in_builder = True

            # Check 6: EXPOSE dangerous ports
            expose_match = re.match(r"^EXPOSE\s+(.+)$", stripped, re.IGNORECASE)
            if expose_match:
                ports_str = expose_match.group(1)
                for port_tok in re.findall(r"(\d+)", ports_str):
                    port = int(port_tok)
                    if port in self.DANGEROUS_PORTS:
                        svc_map = {22: "SSH", 2375: "Docker API (unencrypted)", 2376: "Docker API (TLS)",
                                   6379: "Redis", 27017: "MongoDB", 5432: "PostgreSQL", 3306: "MySQL"}
                        findings.append({
                            "title": f"Dangerous Port Exposed: {port} ({svc_map.get(port, 'unknown')})",
                            "severity": "medium",
                            "category": "docker_network",
                            "description": f"Port {port} ({svc_map.get(port, 'unknown')}) is exposed. Exposing database or management ports increases the attack surface.",
                            "evidence": _ev(fname, idx),
                            "remediation": f"Remove the EXPOSE directive for port {port} or ensure it is only accessible within an internal Docker network.",
                            "line_number": idx,
                        })

            # Check 7: --privileged in RUN
            if re.search(r"--privileged", stripped, re.IGNORECASE):
                findings.append({
                    "title": "--privileged Flag in RUN",
                    "severity": "critical",
                    "category": "docker_privilege",
                    "description": "The --privileged flag in RUN gives the build step full host access. This is almost never needed and is extremely dangerous.",
                    "evidence": _ev(fname, idx),
                    "remediation": "Remove --privileged. If specific capabilities are needed, use --cap-add for individual capabilities.",
                    "line_number": idx,
                })

            # Check 8: apt-get without no-install-recommends or without rm -rf /var/lib/apt
            if "apt-get" in stripped and "install" in stripped:
                if "no-install-recommends" not in stripped:
                    findings.append({
                        "title": "apt-get install Without --no-install-recommends",
                        "severity": "low",
                        "category": "docker_image_size",
                        "description": "apt-get install without --no-install-recommends installs unnecessary recommended packages, increasing image size and attack surface.",
                        "evidence": _ev(fname, idx),
                        "remediation": "Use 'apt-get install --no-install-recommends' to minimize installed packages.",
                        "line_number": idx,
                    })

            # Track USER directive
            if re.match(r"^USER\b", stripped, re.IGNORECASE):
                has_user = True
                user_val = stripped[4:].strip()
                if user_val.lower() in ("root", "0"):
                    if had_nonroot_user:
                        # Check 10: USER changed back to root after being non-root
                        findings.append({
                            "title": "USER Reverted to Root After Non-Root User",
                            "severity": "high",
                            "category": "docker_privilege",
                            "description": "A non-root USER was set earlier, but has been changed back to root. This defeats the purpose of dropping privileges.",
                            "evidence": _ev(fname, idx),
                            "remediation": "Ensure the final USER directive is a non-root user. If root is needed for specific steps, use multi-stage builds.",
                            "line_number": idx,
                        })
                else:
                    had_nonroot_user = True

            # Check 9: HEALTHCHECK
            if re.match(r"^HEALTHCHECK\b", stripped, re.IGNORECASE):
                has_healthcheck = True

        # Check 9 (post-loop): No HEALTHCHECK
        if not has_healthcheck:
            findings.append({
                "title": "No HEALTHCHECK Instruction",
                "severity": "low",
                "category": "docker_monitoring",
                "description": "No HEALTHCHECK instruction found. The container orchestrator cannot determine if the application is healthy.",
                "evidence": f"{fname}: no HEALTHCHECK",
                "remediation": "Add a HEALTHCHECK instruction: HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD <health-command>",
                "line_number": 0,
            })

        # Check 1 (post-loop): Runs as root (no USER directive or USER root)
        if not has_user:
            findings.append({
                "title": "Container Runs as Root",
                "severity": "high",
                "category": "docker_privilege",
                "description": "No USER directive found. The container will run as root by default, giving full control to any process inside the container.",
                "evidence": f"{fname}: no USER directive",
                "remediation": "Add 'USER <non-root-user>' near the end of the Dockerfile. Create a dedicated user with 'RUN useradd -m appuser'.",
                "line_number": 0,
            })
        elif not had_nonroot_user:
            # USER was set but only to root
            findings.append({
                "title": "Container Explicitly Runs as Root",
                "severity": "high",
                "category": "docker_privilege",
                "description": "USER directive is set to root. The container runs with full root privileges inside the container.",
                "evidence": f"{fname}: USER root",
                "remediation": "Change USER to a non-root account. Create a dedicated user and switch to it before ENTRYPOINT/CMD.",
                "line_number": 0,
            })

        # Check apt-get cleanup (post-loop, look for rm -rf /var/lib/apt in any RUN)
        has_apt_install = False
        has_apt_cleanup = False
        for line in lines:
            stripped = line.strip()
            if "apt-get" in stripped and "install" in stripped:
                has_apt_install = True
            if "rm" in stripped and ("/var/lib/apt" in stripped or "/var/cache/apt" in stripped):
                has_apt_cleanup = True
        if has_apt_install and not has_apt_cleanup:
            findings.append({
                "title": "apt-get Cache Not Cleaned",
                "severity": "low",
                "category": "docker_image_size",
                "description": "apt-get install is used but the package cache is not cleaned. This significantly increases image size.",
                "evidence": f"{fname}: missing 'rm -rf /var/lib/apt/lists/*'",
                "remediation": "Combine apt-get install and cleanup in one RUN layer: 'apt-get update && apt-get install --no-install-recommends -y pkg && rm -rf /var/lib/apt/lists/*'",
                "line_number": 0,
            })

        # Check 12: Multi-stage build with secrets in builder stage
        if len(from_lines) > 1 and secret_env_in_builder:
            findings.append({
                "title": "Multi-Stage Build with Secrets in Builder Stage",
                "severity": "high",
                "category": "docker_secret_leak",
                "description": "Multi-stage build detected with ENV secrets in builder stages. Builder stage secrets may persist in build cache or intermediate layers.",
                "evidence": f"{fname}: {len(from_lines)} FROM directives, secrets in ENV",
                "remediation": "Use --secret flag (BuildKit) or pass secrets via ARG with --build-arg. Never use ENV for secrets in builder stages.",
                "line_number": from_lines[1] if len(from_lines) > 1 else 0,
            })

        return findings


# ══════════════════════════════════════════════════════════════════════
#  K8sAnalyzer
# ══════════════════════════════════════════════════════════════════════

class K8sAnalyzer:
    """Analyzes Kubernetes YAML manifests for security misconfigurations."""

    DANGEROUS_CAPS = {"ALL", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN"}
    HOST_MOUNT_PATHS = {"/", "/etc", "/root", "/var/run", "/sys", "/proc"}

    def analyze_file(self, path: str) -> List[Dict[str, Any]]:
        """Analyze a K8s YAML manifest and return a list of finding dicts."""
        findings: List[Dict[str, Any]] = []
        content = _read_file(path)
        if not content or content.startswith("[file too large]"):
            return findings

        fname = os.path.basename(path)
        docs = _yaml_load_all(content)
        kind_counts: Dict[str, int] = {}

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            if kind:
                kind_counts[kind] = kind_counts.get(kind, 0) + 1
            findings.extend(self._analyze_doc(doc, fname, path))

        # Check 17: No NetworkPolicy in namespace
        if "NetworkPolicy" not in kind_counts:
            if any(k in kind_counts for k in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job")):
                findings.append({
                    "title": "No NetworkPolicy Defined",
                    "severity": "low",
                    "category": "k8s_network",
                    "description": "No NetworkPolicy resource found in this manifest. All pods can communicate with each other without restriction.",
                    "evidence": f"{fname}: no NetworkPolicy resource",
                    "remediation": "Define NetworkPolicy resources to restrict pod-to-pod communication. Use default-deny ingress/egress policies.",
                    "line_number": 0,
                })

        # Check 18: Service type LoadBalancer without annotation
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if doc.get("kind") == "Service":
                svc_type = _dict_get(doc, "spec", "type", default="")
                if svc_type == "LoadBalancer":
                    annotations = _dict_get(doc, "metadata", "annotations", default={})
                    if not isinstance(annotations, dict):
                        annotations = {}
                    has_safety_annotation = any(
                        k.lower() for k in annotations
                        if "whitelist" in k.lower() or "allowlist" in k.lower()
                        or "security" in k.lower() or "firewall" in k.lower()
                    )
                    if not has_safety_annotation:
                        findings.append({
                            "title": "LoadBalancer Service Without Security Annotation",
                            "severity": "low",
                            "category": "k8s_network",
                            "description": "Service of type LoadBalancer exposes the service to the internet without any security/whitelist annotation.",
                            "evidence": f"{fname}: Service type=LoadBalancer, no security annotation",
                            "remediation": "Add network restrictions via annotations or use an Ingress with TLS and auth. Consider internal load balancers for non-public services.",
                            "line_number": 0,
                        })

        # Check 19: Ingress without TLS
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if doc.get("kind") == "Ingress":
                tls_config = _dict_get(doc, "spec", "tls")
                if not tls_config:
                    findings.append({
                        "title": "Ingress Without TLS",
                        "severity": "medium",
                        "category": "k8s_network",
                        "description": "Ingress resource has no TLS configuration. Traffic is served over unencrypted HTTP.",
                        "evidence": f"{fname}: Ingress missing spec.tls",
                        "remediation": "Add a TLS section to the Ingress spec with a secretRef to a TLS certificate secret.",
                        "line_number": 0,
                    })

        return findings

    def _analyze_doc(self, doc: Dict[str, Any], fname: str, fpath: str) -> List[Dict[str, Any]]:
        """Analyze a single K8s document."""
        findings: List[Dict[str, Any]] = []
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "<unnamed>") if isinstance(metadata, dict) else "<unnamed>"
        line_prefix = f"{fname}: {kind}/{name}"

        pod_spec = _find_pod_or_template_spec(doc)
        containers = _find_container_specs(doc)

        if pod_spec:
            # Check 3: hostPID
            if pod_spec.get("hostPID") is True:
                findings.append({
                    "title": f"hostPID Enabled: {kind}/{name}",
                    "severity": "high",
                    "category": "k8s_privilege",
                    "description": "hostPID allows the pod to see all processes on the host. An attacker can observe or kill host processes.",
                    "evidence": line_prefix,
                    "remediation": "Remove hostPID: true. Use process namespacing within the container.",
                    "line_number": 0,
                })

            # Check 4: hostNetwork
            if pod_spec.get("hostNetwork") is True:
                findings.append({
                    "title": f"hostNetwork Enabled: {kind}/{name}",
                    "severity": "high",
                    "category": "k8s_privilege",
                    "description": "hostNetwork gives the pod direct access to the host's network namespace. The pod can bind to any host port.",
                    "evidence": line_prefix,
                    "remediation": "Remove hostNetwork: true. Use container ports with a Service for network access.",
                    "line_number": 0,
                })

            # Check 5: hostIPC
            if pod_spec.get("hostIPC") is True:
                findings.append({
                    "title": f"hostIPC Enabled: {kind}/{name}",
                    "severity": "medium",
                    "category": "k8s_privilege",
                    "description": "hostIPC allows the pod to access host IPC resources. This can be used for inter-process attacks.",
                    "evidence": line_prefix,
                    "remediation": "Remove hostIPC: true.",
                    "line_number": 0,
                })

            # Check 10: automountServiceAccountToken
            if pod_spec.get("automountServiceAccountToken") is True:
                findings.append({
                    "title": f"Service Account Token Auto-Mounted: {kind}/{name}",
                    "severity": "medium",
                    "category": "k8s_auth",
                    "description": "automountServiceAccountToken: true mounts the service account token into the pod. If the pod is compromised, the token can be used to access the K8s API.",
                    "evidence": line_prefix,
                    "remediation": "Set automountServiceAccountToken: false unless the pod needs to access the K8s API. Use a minimal RBAC role.",
                    "line_number": 0,
                })

            # Check 20: Pod anti-affinity not set
            replicas = _dict_get(doc, "spec", "replicas", default=1)
            if isinstance(replicas, int) and replicas > 1:
                affinity = pod_spec.get("affinity")
                pod_anti = None
                if isinstance(affinity, dict):
                    pod_anti = affinity.get("podAntiAffinity")
                if not pod_anti:
                    findings.append({
                        "title": f"No Pod Anti-Affinity: {kind}/{name}",
                        "severity": "low",
                        "category": "k8s_availability",
                        "description": f"Deployment has {replicas} replicas but no pod anti-affinity. All pods may be scheduled on the same node (single point of failure).",
                        "evidence": line_prefix,
                        "remediation": "Add podAntiAffinity rules to spread replicas across nodes. Use requiredDuringSchedulingIgnoredDuringExecution with topology key 'kubernetes.io/hostname'.",
                        "line_number": 0,
                    })

            # Check 15: Tolerations for all taints
            tolerations = pod_spec.get("tolerations")
            if isinstance(tolerations, list):
                for tol in tolerations:
                    if isinstance(tol, dict):
                        if (tol.get("effect") == "NoSchedule"
                                and tol.get("operator") == "Exists"
                                and "key" not in tol):
                            findings.append({
                                "title": f"Toleration for All Taints: {kind}/{name}",
                                "severity": "medium",
                                "category": "k8s_scheduling",
                                "description": "Pod tolerates all taints (operator: Exists, no key). This pod can be scheduled on any node including dedicated/master nodes.",
                                "evidence": line_prefix,
                                "remediation": "Specify explicit toleration keys instead of tolerating all taints. Remove or restrict the toleration.",
                                "line_number": 0,
                            })
                            break

        # Per-container checks
        for container in containers:
            if not isinstance(container, dict):
                continue
            cname = container.get("name", "<unnamed>")
            cprefix = f"{line_prefix} container/{cname}"
            sec_ctx = container.get("securityContext", {})
            if not isinstance(sec_ctx, dict):
                sec_ctx = {}

            # Also check pod-level securityContext as fallback
            if not sec_ctx and pod_spec:
                sec_ctx = pod_spec.get("securityContext", {})
                if not isinstance(sec_ctx, dict):
                    sec_ctx = {}

            # Check 1: securityContext.privileged: true
            if sec_ctx.get("privileged") is True:
                findings.append({
                    "title": f"Privileged Container: {cname}",
                    "severity": "critical",
                    "category": "k8s_privilege",
                    "description": f"Container '{cname}' runs in privileged mode. This grants full access to all host devices and effectively removes container isolation.",
                    "evidence": cprefix + " securityContext.privileged: true",
                    "remediation": f"Remove privileged: true for '{cname}'. If specific capabilities are needed, use securityContext.capabilities.add with minimal caps.",
                    "line_number": 0,
                })

            # Check 2: allowPrivilegeEscalation: true
            ape = sec_ctx.get("allowPrivilegeEscalation")
            if ape is True or (ape is None and sec_ctx.get("privileged") is not True):
                # It's a problem when explicitly true; default is true if not set
                if ape is True:
                    findings.append({
                        "title": f"Allow Privilege Escalation: {cname}",
                        "severity": "high",
                        "category": "k8s_privilege",
                        "description": f"Container '{cname}' has allowPrivilegeEscalation: true. Processes can gain additional privileges (e.g., setuid binaries).",
                        "evidence": cprefix + " securityContext.allowPrivilegeEscalation: true",
                        "remediation": f"Set allowPrivilegeEscalation: false for '{cname}' unless explicitly required.",
                        "line_number": 0,
                    })

            # Check 6: Volume mount of docker.sock
            vol_mounts = container.get("volumeMounts", [])
            if isinstance(vol_mounts, list):
                for vm in vol_mounts:
                    if isinstance(vm, dict) and vm.get("mountPath") == "/var/run/docker.sock":
                        findings.append({
                            "title": f"Docker Socket Mounted: {cname}",
                            "severity": "critical",
                            "category": "k8s_escape",
                            "description": f"Container '{cname}' mounts /var/run/docker.sock. Full container escape is trivial from here — the pod can launch privileged containers on the host.",
                            "evidence": cprefix + " mountPath: /var/run/docker.sock",
                            "remediation": "Remove the docker.sock volume mount. If Docker-in-Docker is needed, use a sidecar with Docker socket proxy or use Podman/Systemd.",
                            "line_number": 0,
                        })

                    # Check 7: Host-sensitive path mounted
                    mp = vm.get("mountPath", "") if isinstance(vm, dict) else ""
                    if mp in self.HOST_MOUNT_PATHS:
                        findings.append({
                            "title": f"Host Path Mounted: {mp} in {cname}",
                            "severity": "high",
                            "category": "k8s_escape",
                            "description": f"Container '{cname}' mounts host path '{mp}'. This provides direct access to host filesystem data and configuration.",
                            "evidence": cprefix + f" mountPath: {mp}",
                            "remediation": f"Remove the hostPath volume mount for '{mp}'. Use ConfigMaps, Secrets, or PersistentVolumeClaims instead.",
                            "line_number": 0,
                        })

            # Check 8: No resource limits
            resources = container.get("resources", {})
            if not isinstance(resources, dict) or not resources.get("limits"):
                findings.append({
                    "title": f"No Resource Limits: {cname}",
                    "severity": "medium",
                    "category": "k8s_resources",
                    "description": f"Container '{cname}' has no resource limits defined. A compromised or buggy container can consume all node resources (Denial of Service).",
                    "evidence": cprefix + " missing resources.limits",
                    "remediation": f"Add resource limits for '{cname}': resources.limits.cpu and resources.limits.memory.",
                    "line_number": 0,
                })

            # Check 9: No liveness/readiness probe
            has_liveness = "livenessProbe" in container and container["livenessProbe"]
            has_readiness = "readinessProbe" in container and container["readinessProbe"]
            if not has_liveness and not has_readiness:
                findings.append({
                    "title": f"No Probes: {cname}",
                    "severity": "low",
                    "category": "k8s_monitoring",
                    "description": f"Container '{cname}' has neither livenessProbe nor readinessProbe. The orchestrator cannot detect or recover from failures.",
                    "evidence": cprefix + " missing livenessProbe/readinessProbe",
                    "remediation": f"Add livenessProbe and readinessProbe to '{cname}' to enable automatic health monitoring and restart.",
                    "line_number": 0,
                })

            # Check 11: imagePullPolicy missing
            pull_policy = container.get("imagePullPolicy")
            image = container.get("image", "")
            if not pull_policy and image:
                if ":latest" in image or ":" not in image:
                    findings.append({
                        "title": f"imagePullPolicy Missing (latest tag): {cname}",
                        "severity": "low",
                        "category": "k8s_supply_chain",
                        "description": f"Container '{cname}' uses image '{image}' without explicit imagePullPolicy. Default 'Always' for :latest can lead to supply chain attacks.",
                        "evidence": cprefix + f" image: {image}",
                        "remediation": f"Set imagePullPolicy: IfNotPresent and pin image to a specific tag for '{cname}'.",
                        "line_number": 0,
                    })

            # Check 12: runAsUser: 0
            run_as_user = sec_ctx.get("runAsUser")
            if run_as_user == 0:
                findings.append({
                    "title": f"Container Runs as Root (runAsUser: 0): {cname}",
                    "severity": "high",
                    "category": "k8s_privilege",
                    "description": f"Container '{cname}' has runAsUser: 0. The container process runs as root inside the pod.",
                    "evidence": cprefix + " securityContext.runAsUser: 0",
                    "remediation": f"Set runAsUser to a non-zero UID and runAsNonRoot: true for '{cname}'.",
                    "line_number": 0,
                })

            # Check 13: readOnlyRootFilesystem not true
            read_only = sec_ctx.get("readOnlyRootFilesystem")
            if read_only is not True:
                findings.append({
                    "title": f"Writable Root Filesystem: {cname}",
                    "severity": "medium",
                    "category": "k8s_hardening",
                    "description": f"Container '{cname}' has a writable root filesystem. An attacker can write malicious binaries or modify application code.",
                    "evidence": cprefix + " missing readOnlyRootFilesystem: true",
                    "remediation": f"Set readOnlyRootFilesystem: true for '{cname}' and use emptyDir volumes for directories that need write access.",
                    "line_number": 0,
                })

            # Check 14: Dangerous capabilities
            caps = _dict_get(sec_ctx, "capabilities", "add", default=[])
            if isinstance(caps, list):
                for cap in caps:
                    cap_str = str(cap).upper().replace("CAP_", "")
                    if cap_str in self.DANGEROUS_CAPS:
                        sev = "critical" if cap_str == "ALL" else "high"
                        findings.append({
                            "title": f"Dangerous Capability: CAP_{cap_str} on {cname}",
                            "severity": sev,
                            "category": "k8s_privilege",
                            "description": f"Container '{cname}' adds Linux capability CAP_{cap_str}. This capability can be used for container escape or privilege escalation.",
                            "evidence": cprefix + f" capabilities.add: CAP_{cap_str}",
                            "remediation": f"Remove CAP_{cap_str} from capabilities.add. Apply least-privilege principle — only grant capabilities explicitly needed.",
                            "line_number": 0,
                        })

            # Check 21: Secret mounted as env var (not volume)
            env_list = container.get("env", [])
            if isinstance(env_list, list):
                for env_item in env_list:
                    if isinstance(env_item, dict):
                        val_from = env_item.get("valueFrom")
                        if isinstance(val_from, dict) and "secretKeyRef" in val_from:
                            var_name = env_item.get("name", "<unknown>")
                            findings.append({
                                "title": f"Secret Mounted as Env Var: {var_name} in {cname}",
                                "severity": "medium",
                                "category": "k8s_secret_handling",
                                "description": f"Secret '{var_name}' is mounted as an environment variable in '{cname}'. Env vars are visible in process listings, child processes, and may leak via error messages.",
                                "evidence": cprefix + f" env[{var_name}].valueFrom.secretKeyRef",
                                "remediation": f"Mount the secret as a file (volume) instead of an env var for '{var_name}'. Use secretRef volumes with 0400 permissions.",
                                "line_number": 0,
                            })

        return findings


# ══════════════════════════════════════════════════════════════════════
#  EscapeVectorEvaluator
# ══════════════════════════════════════════════════════════════════════

class EscapeVectorEvaluator:
    """Combines individual findings into compound escape vectors."""

    _PATTERNS = [
        {
            "name": "Full Container Escape",
            "severity": "critical",
            "description": ("Combination of privileged mode, hostPID, and docker.sock access. "
                            "An attacker can access the host, observe all processes, and launch new "
                            "privileged containers — achieving full host compromise."),
            "remediation": "Remove privileged, hostPID, and docker.sock mount. Apply Pod Security Standards (restricted profile).",
            "any_of": [
                {"category": "k8s_privilege", "title_sub": "Privileged Container"},
                {"category": "k8s_privilege", "title_sub": "hostPID"},
                {"category": "k8s_escape", "title_sub": "Docker Socket"},
            ],
        },
        {
            "name": "Network Escape",
            "severity": "high",
            "description": ("Privileged container with hostNetwork access. The container has full access to "
                            "the host's network stack, can sniff all traffic, and bind to any port."),
            "remediation": "Remove hostNetwork: true and privileged: true. Use container networking with Service resources.",
            "any_of": [
                {"category": "k8s_privilege", "title_sub": "Privileged Container"},
                {"category": "k8s_privilege", "title_sub": "hostNetwork"},
            ],
        },
        {
            "name": "Resource Exhaustion to Host",
            "severity": "high",
            "description": ("hostPID access combined with no resource limits. An attacker can fork-bomb the "
                            "container which, via hostPID, can impact host process management."),
            "remediation": "Add resource limits (CPU/memory) and remove hostPID. Use LimitRange at the namespace level.",
            "any_of": [
                {"category": "k8s_privilege", "title_sub": "hostPID"},
                {"category": "k8s_resources", "title_sub": "No Resource Limits"},
            ],
        },
        {
            "name": "Filesystem Escape",
            "severity": "critical",
            "description": ("Privileged container with host root filesystem mounted. The container has "
                            "full read/write access to the host's root filesystem — trivial host compromise."),
            "remediation": "Remove privileged: true and the hostPath '/' volume mount. Use Pod Security Standards (restricted profile).",
            "any_of": [
                {"category": "k8s_privilege", "title_sub": "Privileged Container"},
                {"category": "k8s_escape", "title_sub": "Host Path Mounted: /"},
            ],
        },
        {
            "name": "Kernel Exploit Vector",
            "severity": "high",
            "description": ("Privilege escalation allowed with SYS_ADMIN capability. An attacker can "
                            "exploit kernel vulnerabilities or use SYS_ADMIN to mount filesystems, "
                            "modify network configuration, or access sensitive kernel interfaces."),
            "remediation": "Set allowPrivilegeEscalation: false and remove CAP_SYS_ADMIN. Apply least-privilege capabilities.",
            "any_of": [
                {"category": "k8s_privilege", "title_sub": "Allow Privilege Escalation"},
                {"category": "k8s_privilege", "title_sub": "SYS_ADMIN"},
            ],
        },
        {
            "name": "Lateral Movement",
            "severity": "medium",
            "description": ("No NetworkPolicy combined with exposed services. Pods can communicate freely "
                            "with any other pod in the cluster, enabling lateral movement if compromised."),
            "remediation": "Define NetworkPolicy resources with default-deny rules. Segment pods by function and apply least-access network policies.",
            "any_of": [
                {"category": "k8s_network", "title_sub": "No NetworkPolicy"},
                {"category": "k8s_network", "title_sub": "LoadBalancer"},
            ],
        },
    ]

    def evaluate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify compound escape vectors from individual findings."""
        compound: List[Dict[str, Any]] = []

        for pattern in self._PATTERNS:
            matched_conditions: List[str] = []
            matched_evidence: List[str] = []
            all_match = True

            for condition in pattern["any_of"]:
                found = False
                for f in findings:
                    cat = f.get("category", "")
                    title = f.get("title", "")
                    if cat == condition["category"] and condition["title_sub"] in title:
                        matched_conditions.append(title)
                        matched_evidence.append(f.get("evidence", ""))
                        found = True
                        break
                if not found:
                    all_match = False
                    break

            if all_match:
                compound.append({
                    "title": f"Escape Vector: {pattern['name']}",
                    "severity": pattern["severity"],
                    "category": "container_escape_vector",
                    "description": pattern["description"],
                    "evidence": "; ".join(matched_evidence),
                    "remediation": pattern["remediation"],
                    "line_number": 0,
                    "component_findings": matched_conditions,
                })

        return compound


# ══════════════════════════════════════════════════════════════════════
#  run_container_sec() — module entry point
# ══════════════════════════════════════════════════════════════════════

def run_container_sec(target: str, base_url: str = "", **kwargs: Any) -> List[Finding]:
    """Container sandbox escape analysis.

    Recursively scans a directory for Dockerfiles and Kubernetes manifests,
    runs all analyzers, evaluates compound escape vectors, and returns
    a list of Finding objects.

    Returns:
        List[Finding]
    """
    dockerfile_analyzer = DockerfileAnalyzer()
    k8s_analyzer = K8sAnalyzer()
    escape_evaluator = EscapeVectorEvaluator()

    base = os.path.abspath(target)
    raw_findings: List[Dict[str, Any]] = []

    # Recursively find relevant files
    for root, _dirs, files in os.walk(base):
        for fname in files:
            fpath = os.path.join(root, fname)

            # Dockerfiles (exact name or Dockerfile.*)
            if fname == "Dockerfile" or fname.startswith("Dockerfile."):
                raw_findings.extend(dockerfile_analyzer.analyze(fpath))

            # K8s manifests (*.yaml, *.yml) — but skip docker-compose files
            elif fname.endswith((".yaml", ".yml")):
                if fname not in ("docker-compose.yml", "docker-compose.yaml",
                                  "docker-compose.override.yml", "docker-compose.override.yaml"):
                    # Quick heuristic: only parse files that look like K8s manifests
                    content = _read_file(fpath)
                    if content and ("apiVersion:" in content or "kind:" in content):
                        raw_findings.extend(k8s_analyzer.analyze_file(fpath))

    # Evaluate compound escape vectors
    escape_vectors = escape_evaluator.evaluate(raw_findings)
    raw_findings.extend(escape_vectors)

    # Convert raw dicts to Finding objects
    findings: List[Finding] = []
    total_deducted = 0

    for rf in raw_findings:
        sev = rf.get("severity", "medium").lower()
        dread = rf.get("dread_score", _dread(sev))
        pts = rf.get("points_deducted", _pts(sev))
        total_deducted += pts

        findings.append(Finding(
            title=rf.get("title", "Untitled Finding"),
            severity=sev,
            category=rf.get("category", "container_security"),
            module="container_sec",
            description=rf.get("description", ""),
            evidence=rf.get("evidence", ""),
            asset=target,
            points_deducted=pts,
            dread_score=dread,
            remediation=rf.get("remediation", ""),
        ))

    # Sort: critical first, then high, medium, low, info
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev_order.get(f.severity, 5))

    return findings
