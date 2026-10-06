---
name: appsec-audit
description: Audits web applications, REST/GraphQL APIs, and AI/LLM interfaces against OWASP Top 10 and API Security standards.
---

# Application Security Audit (OWASP & API Security)

This skill provides step-by-step methodologies to conduct application security reviews on codebases and API designs.

## Methodology

1. **Target Identification:**
   - Locate application entry points: HTTP routers, controllers, GraphQL resolvers, and AI prompt templates.
2. **OWASP Top 10 Review:**
   - **A01 Broken Access Control:** Verify authorization checks on every state-changing route and object ID lookup.
   - **A02 Cryptographic Failures:** Check for weak hashing algorithms (MD5, SHA-1), hardcoded encryption keys, or missing TLS.
   - **A03 Injection:** Inspect database queries for parameterization and template renderers for SSTI risks.
   - **A05 Security Misconfiguration:** Verify production debug flags are disabled and CORS policies are scoped.
   - **A10 SSRF:** Validate outbound HTTP request destinations against an allowlist and block private subnet egress.
3. **API Security Top 10 Review:**
   - **BOLA (API1):** Ensure record access checks ownership by the authenticated session.
   - **Mass Assignment (API3):** Confirm models accept only explicitly defined DTO properties.
4. **Prompt Injection & LLM Security:**
   - Ensure user inputs are delimited from system instructions.
   - Never pass raw LLM completions directly into execution sinks (`eval`, shell commands, or unescaped HTML).

## Executable MCP Tools Available:
- `audit_owasp_top10`: Automated scan against OWASP Top 10 patterns.
- `audit_api_security`: Automated scan against OWASP API Security Top 10 patterns.
- `audit_prompt_injection`: Automated scan against LLM prompt injection and output execution risks.
