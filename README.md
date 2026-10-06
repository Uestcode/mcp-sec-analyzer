# MCP Security & Binary Reverse Engineering Suite (REA Equivalent)

Servidor MCP (*Model Context Protocol*) completo para **engenharia reversa, análise estática de binários e triagem de software**, reproduzindo a suíte de ferramentas do [morluto/rea](https://github.com/morluto/rea) com execução local e sem dependência de nuvem.

---

## 🛠️ Matriz de Ferramentas MCP (Equivalência REA)

| Ferramenta MCP | Equivalente REA | Finalidade |
| :--- | :--- | :--- |
| `open_binary` | `open_binary` | Carrega o binário na sessão ativa, descobre arquitetura, image base, entry point e indexa símbolos. |
| `binary_overview` | `binary_overview` | Resumo estrutural: hashes, cálculo de entropia de Shannon (packers/crypto), seções, anomalias (W^X), importações críticas e mitigações (ASLR, DEP/NX, CFG, Authenticode). |
| `search_strings` | `search_strings` | Busca strings (ASCII e UTF-16LE) categorizadas em inteligência (`urls`, `ipv4`, `windows_paths`, `posix_paths`, `registry_keys`, `crypto_pem`, `suspicious_commands`). |
| `list_procedures` | `list_procedures` | Lista e filtra rotinas, pontos de entrada, funções exportadas e importadas com seus endereços virtuais. |
| `read_function_instructions` | `read_function_instructions` | Desmontagem rápida de instruções (via Capstone Engine) com paginação por offset sem o overhead de descompiladores pesados. |
| `get_call_graph` | `get_call_graph` | Reconstrói o grafo de chamadas: funções que chamam (`callers`) e funções chamadas (`callees`). |
| `procedure_pseudo_code` | `procedure_pseudo_code` | Gera pseudocódigo estruturado em estilo C com identificação de argumentos, chamadas e desvios condicionais. |
| `find_xrefs_to_name` | `find_xrefs_to_name` | Encontra referências cruzadas no código (XREFs) para uma função, string literal ou endereço. |
| `detect_framework` | `triage` / `detect` | Identifica o runtime da aplicação: Electron ASAR, .NET/CLR (C#), Go (Golang), Rust, Python PyInstaller, Java JVM ou Nativo C/C++. |
| `inspect_electron_asar` | `asar extract` / `maps` | Inspeciona e extrai pacotes `.asar` do Electron, descobrindo source-maps (`.map`) e `package.json`. |
| `inspect_dotnet` | `dotnet triage` | Inspeciona metadados CLI de montagens .NET, fluxos `#US` (User Strings) e detectores de ofuscadores (ConfuserEx, etc.). |
| `rea_doctor` | `rea doctor` | Diagnóstico de ambiente e integridade dos motores locais (Capstone, formatos suportados e Ghidra Headless). |

---

## 🚀 Como Executar

### Pré-requisitos
- Python 3.11+
- [uv](https://docs.astral.sh/uv/)

### Inicializar Servidor MCP
```bash
uv run python main.py
```

---

## ⚙️ Configuração no Cliente MCP (Claude Desktop, Cursor, Antigravity)

Adicione ao seu arquivo de configuração MCP (`mcp_config.json` ou `claude_desktop_config.json`):

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

---

## 🔄 Fluxo de Investigação Típico (Workflow REA)

1. **Abrir o Binário:** `open_binary("caminho/do/app.exe")`
2. **Obter Visão Geral:** `binary_overview()`
3. **Buscar Pistas & Strings:** `search_strings(category="urls")` ou `search_strings(query="auth")`
4. **Localizar Funções Chave:** `list_procedures(filter_name="Login")`
5. **Rastrear Referências:** `find_xrefs_to_name("https://api.exemplo.com")`
6. **Inspecionar Instruções (Fast-Path):** `read_function_instructions(procedure_or_address="entry_point", limit=20)`
7. **Reconstruir Fluxo de Controle:** `get_call_graph(procedure_or_address="entry_point")`
8. **Gerar Pseudocódigo:** `procedure_pseudo_code(procedure_or_address="entry_point")`
9. **Se for Electron / .NET:** Utilizar `inspect_electron_asar` ou `inspect_dotnet` para extração direta de código-fonte.
