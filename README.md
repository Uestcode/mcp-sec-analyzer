# Multi-Skill Security & Software Analysis MCP Hub

Um servidor MCP (*Model Context Protocol*) modular e extensível para **análise de segurança, engenharia reversa e auditoria de software**, equipado com um **motor de memória persistente local (SQLite)** universal que audita e registra todas as ações de investigação para evitar qualquer perda de contexto pelo agente ou usuário.

---

## 🏛️ Arquitetura Multi-Skill

O servidor funciona como um hub central onde cada domínio de segurança é encapsulado como uma **Skill** independente:

```
MCP/
├── .mcp_memory/                          # Armazenamento SQLite da memória (ignorado no git)
│   └── unified_memory.db
├── src/
│   └── mcp_sec_analyzer/
│       ├── core/                         # Núcleo da plataforma
│       │   ├── memory.py                 # Motor SQLite de persistência e auditoria
│       │   └── decorator.py              # Decorador @skill_tool de rastreamento automático
│       ├── skills/                       # Catálogo de Habilidades
│       │   ├── memory_skill.py           # Ferramentas da Skill de Memória
│       │   └── rea/                      # Skill: Reverse Engineer Anything (REA)
│       │       ├── session.py            # Sessão de análise binária
│       │       ├── triage.py             # Visão geral estrutural e mitigações
│       │       ├── strings_analyzer.py   # Extração inteligente de strings
│       │       ├── disassembler.py       # Desmontagem rápida via Capstone
│       │       ├── call_graph.py         # Grafo de chamadas (callers/callees)
│       │       ├── pseudocode.py         # Decompilador de pseudocódigo C
│       │       ├── xrefs.py              # Referências cruzadas (XREFs)
│       │       ├── framework_detector.py # Detecção de runtime/compilador
│       │       ├── asar.py               # Extração de Electron & source-maps
│       │       ├── dotnet.py             # Análise de .NET / CLI e #US
│       │       └── ghidra_bridge.py      # Diagnóstico e ponte para Ghidra
│       └── server.py                     # Ponto de registro MCP multi-skill
└── main.py                               # Entrypoint stdio
```

---

## 🧠 Skill: Memória Persistente Universal (`memory`)

Tudo que for executado em **qualquer skill** (seja REA ou habilidades futuras) é registrado de forma transparente no banco de dados SQLite local (`.mcp_memory/unified_memory.db`). Além disso, ferramentas dedicadas permitem armazenar notas, hipóteses e recuperar o contexto a qualquer instante:

| Ferramenta | Descrição |
| :--- | :--- |
| `remember` | Salva achados, notas, hipóteses, credenciais ou IOCs com título, tags, categoria (`finding`, `note`, `hypothesis`, `ioc`, `todo`) e referência de alvo. |
| `recall` | Busca na base de conhecimento por palavras-chave, tag, categoria ou skill para recuperar o contexto de investigações anteriores. |
| `get_timeline` | Retorna o histórico cronológico de todas as ferramentas acionadas com status, parâmetros e tempo de execução. |
| `export_investigation_report` | Gera um dossiê completo de investigação formatado em Markdown com sumário da sessão, achados e timeline. |
| `clear_memory` | Limpa a memória de uma skill específica ou todo o banco com confirmação de segurança. |

---

## ⚙️ Skill: Engenharia Reversa (`rea`)

Reproduz 1:1 o conjunto de ferramentas do [morluto/rea](https://github.com/morluto/rea):

| Ferramenta | Descrição |
| :--- | :--- |
| `open_binary` | Carrega o executável na sessão, mapeia arquitetura, ImageBase, EntryPoint e indexa símbolos. |
| `binary_overview` | Hashes, cálculo de entropia de Shannon (detecção de packers/criptografia), seções com anomalias (W^X), importações críticas e mitigações (ASLR, DEP, CFG). |
| `search_strings` | Busca strings (ASCII e UTF-16LE) categorizadas em inteligência (`urls`, `ipv4`, `windows_paths`, `registry_keys`, `crypto_pem`, etc.). |
| `list_procedures` | Lista e filtra rotinas, exportações e importações da sessão ativa. |
| `read_function_instructions` | Desmontagem rápida de instruções (via Capstone Engine) paginada por offset. |
| `get_call_graph` | Reconstrói quem chama a função (`callers`) e quais funções ela invoca (`callees`). |
| `procedure_pseudo_code` | Gera pseudocódigo estruturado em estilo C com convenções de chamada e fluxo de controle. |
| `find_xrefs_to_name` | Encontra referências cruzadas no código (XREFs) para funções, strings literais ou endereços. |
| `detect_framework` | Detecta Electron, .NET C#, Go, Rust, Python PyInstaller, Java JVM ou Nativo C/C++. |
| `inspect_electron_asar` | Inspeciona e extrai arquivos `.asar` do Electron, localizando `package.json` e *source maps* (`.map`). |
| `inspect_dotnet` | Inspeciona montagens .NET, extrai a tabela `#US` (User Strings) e detecta ofuscadores. |
| `rea_doctor` | Executa diagnóstico do ambiente local (Capstone, formatos suportados e detecção do Ghidra Headless). |

---

## 🧭 Meta-Ferramenta

- `list_skills`: Retorna o catálogo das habilidades ativas e ferramentas disponíveis no servidor MCP para os agentes de IA se auto-orientarem.

---

## 🚀 Como Executar e Configurar

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
