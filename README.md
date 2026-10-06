# Multi-Skill Cybersecurity MCP Hub

Servidor MCP (*Model Context Protocol*) avançado e modular que consolida **todas as principais áreas da cibersegurança** em um único hub com **29 ferramentas**, equipado com um motor de **memória persistente universal (SQLite)** para evitar perda de contexto durante análises e investigações.

---

## 🏛️ Catálogo de Habilidades (6 Skills Ativas)

```
MCP/
├── .mcp_memory/                          # Base SQLite da memória (ignorado no git)
│   └── unified_memory.db
├── src/
│   └── mcp_sec_analyzer/
│       ├── core/                         # Núcleo da plataforma
│       │   ├── memory.py                 # Motor SQLite de persistência universal
│       │   └── decorator.py              # Decorador @skill_tool de auditoria automática
│       ├── skills/                       # Habilidades Especializadas
│       │   ├── memory_skill.py           # 1. Memória Persistente e Linha do Tempo
│       │   ├── rea/                      # 2. Engenharia Reversa & Binários (REA)
│       │   ├── security_audit/           # 3. Auditoria de Código, Segredos e CVEs (FuzzingLabs)
│       │   ├── osint_recon/              # 4. Reconhecimento Passivo & Superfície (OSINT)
│       │   ├── threat_intel/             # 5. Inteligência de Ameaças & MITRE ATT&CK
│       │   └── cloud_container/          # 6. Segurança em Nuvem & Hardening de Containers
│       └── server.py                     # Hub MCP Central (Registro de 29 ferramentas)
└── main.py                               # Ponto de entrada stdio
```

---

### 1. 🧠 Universal Memory (`memory`)
Persistência e recuperação de contexto entre sessões de investigação:
- `remember`: Registra achados, notas, hipóteses, credenciais ou IOCs com tags e categorias.
- `recall`: Busca na base de conhecimento local por palavras-chave, tags, categorias ou skills.
- `get_timeline`: Histórico cronológico auditável de tudo que foi executado no servidor.
- `export_investigation_report`: Compila um relatório completo em Markdown.
- `clear_memory`: Limpa a memória de uma skill ou todo o banco com confirmação.

### 2. ⚙️ Engenharia Reversa & Binários (`rea`)
Equivalente completo ao [morluto/rea](https://github.com/morluto/rea):
- `open_binary`: Carrega executável na memória, mapeia ImageBase, EntryPoint e indexa símbolos.
- `binary_overview`: Hashes, cálculo de entropia de Shannon (packers/crypto), seções (W^X) e mitigações (ASLR, DEP, CFG).
- `search_strings`: Busca e categoriza strings ASCII/UTF-16LE (`urls`, `ips`, `registry`, etc.).
- `list_procedures`: Lista e filtra funções, exportações e importações da sessão ativa.
- `read_function_instructions`: Desmontagem rápida de instruções (via Capstone Engine) por offset.
- `get_call_graph`: Reconstrói chamadores (`callers`) e chamadas efetuadas (`callees`).
- `procedure_pseudo_code`: Gera pseudocódigo estruturado em C com argumentos e fluxo de controle.
- `find_xrefs_to_name`: Localiza referências cruzadas no código (XREFs) para símbolos e strings.
- `detect_framework`: Detecta Electron, .NET, Go, Rust, Python PyInstaller, Java ou Nativo.
- `inspect_electron_asar`: Inspeciona/extrai pacotes `.asar`, localizando source maps (`.map`).
- `inspect_dotnet`: Inspeciona metadados .NET CLI, User Strings (`#US`) e ofuscadores.
- `rea_doctor`: Diagnóstico do ambiente e verificação de disassemblers locais e Ghidra.

### 3. 🔍 Auditoria Defensiva & Higiene de Código (`security_audit`)
Inspirado nas categorias defensivas do [FuzzingLabs/mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub):
- `scan_secrets`: Varre repositórios em busca de tokens expostos (AWS, GitHub, Slack, PEM, chaves de API) com redação segura (estilo Gitleaks).
- `audit_dependencies`: Inspeciona manifestos (`requirements.txt`, `package.json`, `pyproject.toml`) consultando a base aberta do **OSV.dev** para apontar CVEs conhecidos (estilo Trivy).
- `run_sast_scan`: Análise estática de código que detecta injeção de comandos, deserialização insegura, SQL formatado e criptografia obsoleta.

### 4. 🌐 Reconhecimento Passivo & Superfície Exposta (`osint_recon`)
Avaliação de postura de rede e web:
- `inspect_http_headers`: Avalia cabeçalhos de proteção (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) e detecta vazamento de banners do servidor (`Server`, `X-Powered-By`).
- `inspect_tls_certificate`: Inspeciona certificados SSL/TLS, cadeia de emissão, SANs, versões de protocolo (TLS 1.2/1.3) e alerta sobre expiração iminente.
- `lookup_dns_records`: Consulta endereços IP (v4/v6), registros MX de e-mail e audita as políticas de **SPF** e **DMARC** contra spoofing de domínio via DNS-over-HTTPS.

### 5. 🎯 Inteligência de Ameaças (`threat_intel`)
Mapeamento e correlação de táticas defensivas:
- `map_mitre_attack`: Mapeia comportamentos, APIs suspeitas ou palavras-chave para a matriz **MITRE ATT&CK Enterprise**, retornando táticas, IDs de técnica e mitigações defensivas.
- `analyze_ioc_indicator`: Classifica e valida Indicadores de Comprometimento (IP, hash, URL, domínio, CVE) aplicando *defanging* seguro (`hxxp://`, `domain[.]com`) e sugerindo ações de hunting.
- `lookup_cve_details`: Consulta detalhes oficiais de vulnerabilidades e pacotes afetados a partir do identificador CVE.

### 6. ☁️ Segurança em Nuvem & Hardening (`cloud_container`)
Auditoria de postura em infraestrutura moderna:
- `audit_dockerfile`: Inspeciona Dockerfiles contra os benchmarks de segurança **CIS Docker** (execução como root, imagens base não fixadas, pipes `curl|sh`, ausência de healthcheck).
- `audit_iam_policy`: Audita políticas de identidade e acesso (IAM) em busca de permissões excessivas coringadas (`*` em `*`), acessos administrativos irrestritos e riscos de escalonamento de privilégios.

---

## 🧭 Metadados e Auto-Orientação de IA

- `list_skills`: Permite que qualquer agente de IA explore em tempo de execução o catálogo completo de habilidades ativas e ferramentas disponíveis no servidor.

---

## 🚀 Como Executar

```bash
uv run python main.py
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
