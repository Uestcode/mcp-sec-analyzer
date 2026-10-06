# Unified Cybersecurity MCP Hub

Servidor MCP (*Model Context Protocol*) avançado e modular que consolida **todas as principais áreas da cibersegurança** em um único hub com **34 ferramentas executáveis** organizadas em **8 habilidades ativas**, equipado com um motor de **memória persistente universal (SQLite)** e playbooks em padrão **Agent Skills**.

---

## 🏛️ Catálogo de Habilidades (8 Skills Ativas)

```
MCP/
├── .agents/skills/                       # Playbooks de Habilidades para Agentes de IA
│   ├── appsec-audit/SKILL.md             # Guia de auditoria OWASP e APIs
│   ├── incident-triage/SKILL.md          # Guia de resposta a incidentes NIST
│   └── cloud-iam-audit/SKILL.md          # Guia de hardening e IAM
├── .mcp_memory/                          # Base SQLite da memória (ignorado no git)
│   └── unified_memory.db
├── src/
│   └── mcp_sec_analyzer/
│       ├── core/                         # Núcleo da plataforma
│       │   ├── memory.py                 # Motor SQLite de persistência universal
│       │   └── decorator.py              # Decorador @skill_tool de auditoria automática
│       ├── skills/                       # Habilidades Especializadas
│       │   ├── memory_skill.py           # 1. Memória Persistente e Linha do Tempo (5 ferramentas)
│       │   ├── rea/                      # 2. Engenharia Reversa & Binários REA (12 ferramentas)
│       │   ├── security_audit/           # 3. Auditoria de Código, Segredos e CVEs (3 ferramentas)
│       │   ├── appsec/                   # 4. AppSec, OWASP Top 10 e Prompt Injection (3 ferramentas)
│       │   ├── osint_recon/              # 5. Reconhecimento Passivo & Superfície (3 ferramentas)
│       │   ├── threat_intel/             # 6. Inteligência de Ameaças & MITRE ATT&CK (3 ferramentas)
│       │   ├── cloud_container/          # 7. Segurança em Nuvem & Containers (2 ferramentas)
│       │   └── incident_response/        # 8. Forense Digital & Resposta a Incidentes (2 ferramentas)
│       └── server.py                     # Hub MCP Central (34 ferramentas registradas)
└── main.py                               # Ponto de entrada stdio
```

---

## 🛠️ Matriz Geral das 34 Ferramentas

| Habilidade | Ferramentas | Descrição e Frameworks |
| :--- | :--- | :--- |
| **`memory`** | `remember`<br>`recall`<br>`get_timeline`<br>`export_investigation_report`<br>`clear_memory` | Base SQLite local (`.mcp_memory/unified_memory.db`) que audita todas as ações, registra achados e exporta relatórios Markdown. |
| **`rea`** | `open_binary`<br>`binary_overview`<br>`search_strings`<br>`list_procedures`<br>`read_function_instructions`<br>`get_call_graph`<br>`procedure_pseudo_code`<br>`find_xrefs_to_name`<br>`detect_framework`<br>`inspect_electron_asar`<br>`inspect_dotnet`<br>`rea_doctor` | Suíte REA completa: desmontagem rápida via Capstone, pseudocódigo em C, grafos de chamada, XREFs, Electron ASAR e .NET CLI. |
| **`security_audit`** | `scan_secrets`<br>`audit_dependencies`<br>`run_sast_scan` | Detecção de segredos (estilo Gitleaks), checagem de CVEs via **OSV.dev** (estilo Trivy) e SAST contra injeção de comandos, SQL e deserialização. |
| **`appsec`** | `audit_owasp_top10`<br>`audit_api_security`<br>`audit_prompt_injection` | Auditoria de código contra **OWASP Top 10 (2021)**, **OWASP API Security Top 10 (2023)** e salvaguardas contra **Prompt Injection em LLMs**. |
| **`osint_recon`** | `inspect_http_headers`<br>`inspect_tls_certificate`<br>`lookup_dns_records` | Avaliação de cabeçalhos de segurança (HSTS, CSP), certificados SSL/TLS (validade, SANs) e postura de e-mail (**SPF** e **DMARC**) via DNS-over-HTTPS. |
| **`threat_intel`** | `map_mitre_attack`<br>`analyze_ioc_indicator`<br>`lookup_cve_details` | Mapeamento de TTPs no **MITRE ATT&CK Enterprise**, classificação e *defanging* seguro de IOCs (`hxxp://`, `ip[.]com`) e consulta de CVEs oficiais. |
| **`cloud_container`** | `audit_dockerfile`<br>`audit_iam_policy` | Auditoria de Dockerfiles contra benchmarks **CIS Docker** e análise de privilégios excessivos e escalonamento em políticas IAM de nuvem. |
| **`incident_response`** | `triage_security_incident`<br>`generate_incident_comms` | Triagem de incidentes com classificação P1-P4 (NIST SP 800-61r2), plano de contenção, cadeia de custódia e geração de comunicados técnicos/executivos. |

---

## 🚀 Como Executar e Testar

```bash
uv run python main.py
```

Para rodar a suíte completa de testes de todas as 8 habilidades:
```bash
uv run python tests/test_hub.py
```

### Configuração no Cliente MCP (Antigravity IDE, Claude Desktop, Cursor)

```json
{
  "mcpServers": {
    "mcp-sec-analyzer": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "C:\\Users\\Ruan Oliveira\\Documents\\Programação APP\\MCP",
        "python",
        "main.py"
      ]
    }
  }
}
```
