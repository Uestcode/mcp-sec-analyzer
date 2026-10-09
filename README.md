# Unified Cybersecurity MCP Hub

Servidor MCP (*Model Context Protocol*) avançado e modular que consolida **todas as principais áreas da cibersegurança** em um único hub com **36 ferramentas executáveis** organizadas em **8 habilidades ativas**, equipado com um motor de **memória persistente universal (SQLite)**, playbooks em padrão **Agent Skills** e uma **Interface Web SOC Interativa**.

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
│       │   ├── osint_recon/              # 5. Reconhecimento Passivo & Superfície / Maigret (5 ferramentas)
│       │   ├── threat_intel/             # 6. Inteligência de Ameaças & MITRE ATT&CK (3 ferramentas)
│       │   ├── cloud_container/          # 7. Segurança em Nuvem & Containers (2 ferramentas)
│       │   └── incident_response/        # 8. Forense Digital & Resposta a Incidentes (2 ferramentas)
│       ├── web/                          # Console Web SOC Interativo (Starlette + Vanilla CSS/JS)
│       │   ├── api.py                    # REST API e ponte de execução MCP
│       │   └── static/                   # Frontend SOC (Dark Mode Cyberpunk, visualizador e timeline)
│       └── server.py                     # Hub MCP Central (36 ferramentas registradas)
├── web.py                                # Launcher do Dashboard Web (porta 8000)
└── main.py                               # Ponto de entrada stdio MCP
```

---

## 🛠️ Matriz Geral das 36 Ferramentas

| Habilidade | Ferramentas | Descrição e Frameworks |
| :--- | :--- | :--- |
| **`memory`** | `remember`<br>`recall`<br>`get_timeline`<br>`export_investigation_report`<br>`clear_memory` | Base SQLite local (`.mcp_memory/unified_memory.db`) que audita todas as ações, registra achados e exporta relatórios Markdown. |
| **`rea`** | `open_binary`<br>`binary_overview`<br>`search_strings`<br>`list_procedures`<br>`read_function_instructions`<br>`get_call_graph`<br>`procedure_pseudo_code`<br>`find_xrefs_to_name`<br>`detect_framework`<br>`inspect_electron_asar`<br>`inspect_dotnet`<br>`rea_doctor` | Suíte REA completa: desmontagem rápida via Capstone, pseudocódigo em C, grafos de chamada, XREFs, Electron ASAR e .NET CLI. |
| **`security_audit`** | `scan_secrets`<br>`audit_dependencies`<br>`run_sast_scan` | Detecção de segredos (estilo Gitleaks), checagem de CVEs via **OSV.dev** (estilo Trivy) e SAST contra injeção de comandos, SQL e deserialização. |
| **`appsec`** | `audit_owasp_top10`<br>`audit_api_security`<br>`audit_prompt_injection` | Auditoria de código contra **OWASP Top 10 (2021)**, **OWASP API Security Top 10 (2023)** e salvaguardas contra **Prompt Injection em LLMs**. |
| **`osint_recon`** | `search_username_maigret`<br>`get_maigret_stats`<br>`inspect_http_headers`<br>`inspect_tls_certificate`<br>`lookup_dns_records`<br>`configure_stealth_mode`<br>`test_tor_connectivity` | **Maigret OSINT v0.6.6**: Dossiê e pegada digital em mais de 3.000 sites e redes sociais. Avaliação de cabeçalhos HTTP, certificados SSL/TLS, postura DNS (SPF/DMARC) e **Modo Stealth com nó Onion (Tor SOCKS5h)** para camuflagem de tráfego de rede e OpSec. |
| **`threat_intel`** | `map_mitre_attack`<br>`analyze_ioc_indicator`<br>`lookup_cve_details` | Mapeamento de TTPs no **MITRE ATT&CK Enterprise**, classificação e *defanging* seguro de IOCs (`hxxp://`, `ip[.]com`) e consulta de CVEs oficiais. |
| **`cloud_container`** | `audit_dockerfile`<br>`audit_iam_policy` | Auditoria de Dockerfiles contra benchmarks **CIS Docker** e análise de privilégios excessivos e escalonamento em políticas IAM de nuvem. |
| **`incident_response`** | `triage_security_incident`<br>`generate_incident_comms` | Triagem de incidentes com classificação P1-P4 (NIST SP 800-61r2), plano de contenção, cadeia de custódia e geração de comunicados técnicos/executivos. |

---

## 🧅 Modo Stealth & Camuflagem via Nó Onion (Tor)

O hub inclui um sistema avançado de privacidade e anonimização de tráfego de rede:
- **Túnel SOCKS5h**: Roteia conexões HTTP/HTTPS e consultas DNS remotamente pela rede Tor, blindando contra vazamento de DNS (*DNS leaks*).
- **Compatibilidade Nativa**: Funciona com o daemon oficial do Tor (`127.0.0.1:9050`), Tor Browser (`127.0.0.1:9150`) ou proxies SOCKS5 customizados.
- **Integração nas Ferramentas**: As ferramentas `search_username_maigret` e `inspect_http_headers` respeitam o modo stealth global ou aceitam flags individuais `use_tor: true`.
- **Diagnóstico em Tempo Real**: Ferramenta `test_tor_connectivity` e botão na interface web para checar se o circuito Tor está ativo e identificar o IP de saída camuflado.

---

## 🌐 Como Executar o Dashboard Web Interativo

Para abrir o console SOC completo no navegador e executar ferramentas com 1-clique:

```bash
uv run python web.py --open
```

Acesse em: **`http://127.0.0.1:8000`**

### Recursos do Dashboard Web:
- **Menu Lateral Inteligente**: Recolhe automaticamente ao selecionar uma função para liberar espaço total ao workbench e aos parâmetros, com botão de alternância `◀` / `▶` e atalho `Alt+M` ou `Ctrl+K`.
- **Formulários Dinâmicos**: Detecta tipos, campos de código e gera botões com preenchimento de exemplos com dados reais para cada ferramenta.
- **Visualizador Inteligente**: Cartões visuais de perfis do Maigret com fotos/links diretos, gráficos circulares de pontuação de segurança, badges de severidade e inspetor JSON.
- **Linha do Tempo e Memória**: Histórico persistente gravado em SQLite e exportação de dossiê em Markdown.

---

## 🚀 Como Executar o Servidor MCP (stdio)

```bash
uv run python main.py
```

Para rodar a suíte completa de testes:
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
