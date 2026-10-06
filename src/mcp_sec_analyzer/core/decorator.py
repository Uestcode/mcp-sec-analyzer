"""Universal tool tracking decorator for multi-skill MCP logging."""

from __future__ import annotations

import functools
import time
from typing import Any, Callable

from .memory import unified_memory


def skill_tool(
    skill: str,
    summarizer: Callable[[str, dict[str, Any], Any], str] | None = None,
):
    """Decorator to automatically capture, time, and record tool executions into universal memory."""

    def decorator(func: Callable[..., Any]):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            tool_name = func.__name__
            start_time = time.perf_counter()
            call_args = kwargs.copy()
            if args:
                call_args["_args"] = [str(a) for a in args]

            try:
                result = func(*args, **kwargs)
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

                # Generate concise activity summary
                if summarizer:
                    summary = summarizer(tool_name, call_args, result)
                else:
                    summary = _default_summarizer(skill, tool_name, call_args, result)

                status = "error" if isinstance(result, dict) and "error" in result else "success"

                unified_memory.log_activity(
                    skill=skill,
                    tool_name=tool_name,
                    arguments=call_args,
                    summary=summary,
                    status=status,
                    duration_ms=duration_ms,
                )
                return result
            except Exception as e:
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                unified_memory.log_activity(
                    skill=skill,
                    tool_name=tool_name,
                    arguments=call_args,
                    summary=f"Failed with exception: {e}",
                    status="error",
                    duration_ms=duration_ms,
                )
                raise

        return wrapper

    return decorator


def _default_summarizer(skill: str, tool_name: str, args: dict[str, Any], result: Any) -> str:
    """Generate meaningful summaries across different tools and skills."""
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"

    # REA specific summarizers
    if tool_name == "open_binary":
        return f"Opened '{result.get('file_name', 'binary')}' ({result.get('architecture')}, {result.get('format')})"
    if tool_name == "binary_overview":
        return f"Overview '{result.get('file_name', 'binary')}': Entropy={result.get('overall_entropy', 0):.2f}"
    if tool_name == "search_strings":
        return f"Strings: found {result.get('results_returned', 0)} matches (category: {result.get('requested_category')})"
    if tool_name == "list_procedures":
        return f"Procedures: listed {result.get('returned_count', 0)} of {result.get('total_discovered', 0)}"
    if tool_name == "read_function_instructions":
        return f"Disassembled {result.get('instructions_returned', 0)} instructions at '{result.get('resolved_procedure')}'"
    if tool_name == "get_call_graph":
        return f"Call graph '{result.get('procedure_name')}': {result.get('total_callers', 0)} callers, {result.get('total_callees', 0)} callees"
    if tool_name == "procedure_pseudo_code":
        return f"Generated {result.get('total_lines', 0)} lines of pseudocode for '{result.get('procedure_name')}'"
    if tool_name == "find_xrefs_to_name":
        return f"Found {result.get('xrefs_found', 0)} XREFs to '{args.get('target_name')}'"
    if tool_name == "detect_framework":
        fws = [f["framework"] for f in result.get("detected_frameworks", [])]
        return f"Frameworks: {', '.join(fws) if fws else 'Native'}"
    if tool_name == "inspect_electron_asar":
        return f"ASAR: processed {result.get('total_files', result.get('files_extracted', 0))} files"
    if tool_name == "inspect_dotnet":
        return f".NET: CLR {result.get('clr_version', 'N/A')}, {result.get('user_strings_count', 0)} user strings"
    if tool_name == "rea_doctor":
        return f"Doctor: status={result.get('status')}"

    # Security Audit summarizers
    if tool_name == "scan_secrets":
        return f"Secrets scan: found {result.get('secrets_detected', 0)} secrets in {result.get('files_scanned', 0)} files"
    if tool_name == "audit_dependencies":
        return f"Dependency audit: checked {result.get('packages_checked', 0)} packages, {result.get('vulnerable_packages_found', 0)} vulnerable"
    if tool_name == "run_sast_scan":
        return f"SAST scan: found {result.get('sast_issues_detected', 0)} issues in {result.get('source_files_scanned', 0)} files"

    # OSINT & Recon summarizers
    if tool_name == "inspect_http_headers":
        return f"HTTP headers for '{result.get('url')}': score={result.get('security_score_percentage')}%"
    if tool_name == "inspect_tls_certificate":
        return f"TLS cert '{result.get('hostname')}': {result.get('tls_version')}, expires in {result.get('days_until_expiration')} days"
    if tool_name == "lookup_dns_records":
        sp = result.get('email_security_posture', {})
        return f"DNS posture for '{result.get('domain')}': SPF={sp.get('spf_assessment', 'N/A')}, DMARC={sp.get('dmarc_assessment', 'N/A')}"

    # Threat Intel summarizers
    if tool_name == "map_mitre_attack":
        return f"MITRE ATT&CK: mapped '{result.get('query')}' to {result.get('techniques_matched', 0)} techniques"
    if tool_name == "analyze_ioc_indicator":
        return f"IOC analysis: '{result.get('raw_indicator')}' classified as {result.get('type')}"
    if tool_name == "lookup_cve_details":
        return f"CVE lookup for '{result.get('cve_id')}': {result.get('summary', 'Done')[:50]}"

    # Cloud & Container Hardening summarizers
    if tool_name == "audit_dockerfile":
        return f"Dockerfile audit: {result.get('issues_detected', 0)} issues detected"
    if tool_name == "audit_iam_policy":
        return f"IAM policy audit: {result.get('risks_identified', 0)} privilege risks identified"

    # Memory specific summarizers
    if tool_name == "remember":
        return f"Saved [{result.get('category', 'note').upper()}]: '{result.get('title')}' (tags: {result.get('tags')})"
    if tool_name == "recall":
        return f"Recalled {len(result) if isinstance(result, list) else 0} memory items"
    if tool_name == "get_timeline":
        return f"Retrieved timeline ({len(result) if isinstance(result, list) else 0} events)"
    if tool_name == "export_investigation_report":
        return "Generated full investigation dossier/report"

    return f"Executed {tool_name} under skill '{skill}'"
