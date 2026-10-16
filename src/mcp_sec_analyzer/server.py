"""Multi-Skill MCP Server: General Security & Software Analysis Hub."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from .core.decorator import skill_tool
from .skills.memory_skill import (
    clear_memory as _clear_memory,
    export_investigation_report as _export_investigation_report,
    get_timeline as _get_timeline,
    recall as _recall,
    remember as _remember,
)
from .skills.rea.asar import extract_asar_archive, inspect_asar
from .skills.rea.call_graph import build_call_graph
from .skills.rea.disassembler import disassemble_window
from .skills.rea.dotnet import inspect_dotnet_assembly
from .skills.rea.framework_detector import detect_framework as _detect_framework
from .skills.rea.ghidra_bridge import check_ghidra_status
from .skills.rea.pseudocode import generate_pseudocode
from .skills.rea.session import active_session
from .skills.rea.strings_analyzer import analyze_strings as _analyze_strings
from .skills.rea.triage import triage_file as _triage_file
from .skills.rea.xrefs import find_xrefs_to_name as _find_xrefs_to_name
from .skills.security_audit.dependencies import audit_dependencies as _audit_dependencies
from .skills.security_audit.sast import run_sast_scan as _run_sast_scan
from .skills.security_audit.secrets import scan_secrets as _scan_secrets
from .skills.osint_recon import (
    configure_stealth_mode as _configure_stealth_mode,
    get_maigret_stats as _get_maigret_stats,
    inspect_http_headers as _inspect_http_headers,
    inspect_tls_certificate as _inspect_tls_certificate,
    lookup_dns_records as _lookup_dns_records,
    search_username_maigret as _search_username_maigret,
    test_tor_connectivity as _test_tor_connectivity,
)
from .skills.threat_intel.intel import (
    map_mitre_attack as _map_mitre_attack,
    analyze_ioc_indicator as _analyze_ioc_indicator,
    lookup_cve_details as _lookup_cve_details,
)
from .skills.cloud_container.hardening import (
    audit_dockerfile as _audit_dockerfile,
    audit_iam_policy as _audit_iam_policy,
)
from .skills.appsec.owasp import (
    audit_owasp_top10 as _audit_owasp_top10,
    audit_api_security as _audit_api_security,
)
from .skills.appsec.llm_sec import audit_prompt_injection as _audit_prompt_injection
from .skills.incident_response.triage import (
    triage_security_incident as _triage_security_incident,
    generate_incident_comms as _generate_incident_comms,
)

# Initialize MCP Server instance
server = MCPServer(
    name="mcp-sec-analyzer",
    version="3.0.0",
    description="Hub Unificado de Cibersegurança: REA, AppSec, OWASP, Cloud Hardening, Threat Intel e Resposta a Incidentes",
)

# ============================================================================
# META-SKILL: SKILL CATALOG
# ============================================================================

@server.tool()
def list_skills() -> dict[str, Any]:
    """Lista as habilidades ativas, capacidades e ferramentas integradas neste servidor MCP."""
    return {
        "platform": "Unified Cybersecurity MCP Hub",
        "total_active_skills": 8,
        "active_skills": [
            {
                "id": "memory",
                "name": "Memória Persistente Universal de Investigação e Contexto",
                "status": "active",
                "description": "Banco SQLite local com histórico e timeline de investigações, prevenindo perda de contexto.",
                "tools": ["remember", "recall", "get_timeline", "export_investigation_report", "clear_memory"],
            },
            {
                "id": "rea",
                "name": "Engenharia Reversa Abrangente (Toolkit REA)",
                "status": "active",
                "description": "Desmontagem nativa de binários, grafo de chamadas, pseudocódigo, referências cruzadas (XREFs), pacotes Electron ASAR e triage de assemblies .NET.",
                "tools": [
                    "open_binary", "binary_overview", "search_strings", "list_procedures",
                    "read_function_instructions", "get_call_graph", "procedure_pseudo_code",
                    "find_xrefs_to_name", "detect_framework", "inspect_electron_asar",
                    "inspect_dotnet", "rea_doctor",
                ],
            },
            {
                "id": "security_audit",
                "name": "Auditoria de Segurança e Higiene de Código (SAST / Gitleaks / Trivy)",
                "status": "active",
                "description": "Detecção de vazamento de segredos, auditoria de dependências/CVEs via OSV.dev e regras SAST de código.",
                "tools": ["scan_secrets", "audit_dependencies", "run_sast_scan"],
            },
            {
                "id": "appsec",
                "name": "Segurança de Aplicações & Auditoria OWASP / LLMs",
                "status": "active",
                "description": "Avaliação de código OWASP Top 10, revisão de APIs REST/GraphQL e proteção contra injeção de prompt em LLMs.",
                "tools": ["audit_owasp_top10", "audit_api_security", "audit_prompt_injection"],
            },
            {
                "id": "osint_recon",
                "name": "Reconhecimento Passivo & Superfície Exposta (OSINT / Maigret)",
                "status": "active",
                "description": "Cabeçalhos de segurança HTTP, análise de certificados SSL/TLS, postura DNS/SPF/DMARC e investigação de perfis Maigret em mais de 3.000 sites.",
                "tools": [
                    "inspect_http_headers",
                    "inspect_tls_certificate",
                    "lookup_dns_records",
                    "search_username_maigret",
                    "get_maigret_stats",
                    "configure_stealth_mode",
                    "test_tor_connectivity",
                ],
            },
            {
                "id": "threat_intel",
                "name": "Inteligência de Ameaças & Defesa MITRE ATT&CK",
                "status": "active",
                "description": "Mapeamento de técnicas MITRE ATT&CK, validação e neutralização (defang) de IOCs e consulta de CVEs.",
                "tools": ["map_mitre_attack", "analyze_ioc_indicator", "lookup_cve_details"],
            },
            {
                "id": "cloud_container",
                "name": "Segurança em Nuvem & Hardening de Containers",
                "status": "active",
                "description": "Auditoria de Dockerfiles com CIS Benchmarks e análise de privilégio mínimo em políticas IAM AWS/Nuvem.",
                "tools": ["audit_dockerfile", "audit_iam_policy"],
            },
            {
                "id": "incident_response",
                "name": "Forense Digital & Resposta a Incidentes (DFIR / NIST SP 800-61r2)",
                "status": "active",
                "description": "Triagem rápida de incidentes, planos de contenção, preservação de evidências e comunicados formais por público.",
                "tools": ["triage_security_incident", "generate_incident_comms"],
            },
        ],
        "extensibility": "Arquitetura modular permite adicionar novas habilidades e domínios de segurança facilmente.",
    }


# ============================================================================
# SKILL: UNIVERSAL INVESTIGATION MEMORY
# ============================================================================

@server.tool()
def remember(
    title: str,
    content: str,
    category: str = "finding",
    tags: list[str] | str | None = None,
    skill: str = "general",
    target_ref: str | None = None,
) -> dict[str, Any]:
    """Salva uma observação, insight, hipótese, IOC ou anotação na memória persistente da investigação.

    Args:
        title: Título descritivo da descoberta ou anotação.
        content: Conteúdo detalhado, evidências ou anotações observadas.
        category: Categoria do registro ('finding', 'hypothesis', 'ioc', 'vulnerability', 'note').
        tags: Lista ou string de tags separadas por vírgula.
        skill: Habilidade de segurança relacionada (ex: 'osint_recon', 'appsec').
        target_ref: Referência do alvo ou ativo investigado.
    """
    return _remember(
        title=title,
        content=content,
        category=category,
        tags=tags,
        skill=skill,
        target_ref=target_ref,
    )


@server.tool()
def recall(
    query: str | None = None,
    skill: str | None = None,
    tag: str | None = None,
    category: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Pesquisa e recupera descobertas, anotações e contexto gravados na memória persistente.

    Args:
        query: Termo ou palavra-chave para buscar no título e conteúdo.
        skill: Filtrar registros por habilidade específica.
        tag: Filtrar por tag ou marcador específico.
        category: Filtrar por categoria específica.
        limit: Quantidade máxima de registros a retornar (padrão: 20).
    """
    return _recall(
        query=query,
        skill=skill,
        tag=tag,
        category=category,
        limit=limit,
    )


@server.tool()
def get_timeline(
    skill: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Recupera o histórico cronológico de ações executadas em uma ou todas as habilidades.

    Args:
        skill: Filtrar histórico por habilidade específica (opcional).
        limit: Quantidade máxima de eventos recentes a retornar (padrão: 50).
    """
    return _get_timeline(skill=skill, limit=limit)


@server.tool()
def export_investigation_report(
    skill: str | None = None,
) -> str:
    """Gera e exporta relatório e dossiê completo de investigação em formato Markdown.

    Args:
        skill: Filtrar dossiê por habilidade específica (opcional).
    """
    return _export_investigation_report(skill=skill)


@server.tool()
def clear_memory(
    confirm: bool = False,
    skill: str | None = None,
) -> dict[str, str]:
    """Limpa registros da memória permanente para uma habilidade específica ou todo o banco.

    Args:
        confirm: Confirmação obrigatória para resetar a memória (deve ser True).
        skill: Habilidade específica cujos dados devem ser apagados (opcional).
    """
    return _clear_memory(confirm=confirm, skill=skill)


# ============================================================================
# SKILL: REA (REVERSE ENGINEER ANYTHING)
# ============================================================================

@server.tool()
@skill_tool(skill="rea")
def open_binary(file_path: str) -> dict[str, Any]:
    """Abre e registra um arquivo binário executável na sessão de análise ativa do REA.

    Args:
        file_path: Caminho completo para o arquivo binário (PE, ELF ou Mach-O).
    """
    try:
        return active_session.load(file_path)
    except Exception as e:
        return {"error": str(e)}


@server.tool()
@skill_tool(skill="rea")
def binary_overview(file_path: str | None = None) -> dict[str, Any]:
    """Fornece visão geral estrutural do binário (arquitetura, seções, hashes e proteções DEP/ASLR).

    Args:
        file_path: Caminho opcional do arquivo binário (se omitido, usa a sessão ativa).
    """
    target = file_path or (str(active_session.file_path) if active_session.file_path else None)
    if not target:
        return {"error": "Nenhum binário especificado e nenhuma sessão ativa. Execute 'open_binary' primeiro."}
    return _triage_file(target)


@server.tool()
@skill_tool(skill="rea")
def search_strings(
    query: str | None = None,
    category: str = "all",
    min_length: int = 5,
    max_results: int = 100,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Busca e classifica heuristicamente strings legíveis dentro do binário (ASCII e Unicode).

    Args:
        query: Termo de busca textual para filtrar as strings encontradas.
        category: Categoria de strings a filtrar ('all', 'urls', 'paths', 'registry', 'crypto').
        min_length: Comprimento mínimo de caracteres da string (padrão: 5).
        max_results: Limite máximo de resultados retornados (padrão: 100).
        file_path: Caminho opcional do binário (se omitido, usa a sessão ativa).
    """
    target = file_path or (str(active_session.file_path) if active_session.file_path else None)
    if not target:
        return {"error": "Nenhum binário especificado e nenhuma sessão ativa. Execute 'open_binary' primeiro."}
    return _analyze_strings(
        target_path=target,
        min_length=min_length,
        category=category,
        search_filter=query,
        max_results=max_results,
    )


@server.tool()
@skill_tool(skill="rea")
def list_procedures(filter_name: str | None = None, limit: int = 100) -> dict[str, Any]:
    """Lista procedimentos, funções, símbolos exportados e tabelas de importação do binário ativo.

    Args:
        filter_name: Filtro textual opcional para o nome da função ou procedimento.
        limit: Limite máximo de procedimentos a retornar (padrão: 100).
    """
    if not active_session.is_loaded():
        return {"error": "Nenhum binário carregado no momento. Use 'open_binary' primeiro."}

    procs = list(active_session.procedures.values())
    if filter_name:
        fn_lower = filter_name.lower()
        procs = [p for p in procs if fn_lower in p["name"].lower()]

    return {
        "binary": active_session.file_path.name if active_session.file_path else "",
        "total_discovered": len(active_session.procedures),
        "returned_count": min(len(procs), limit),
        "procedures": procs[:limit],
    }


@server.tool()
@skill_tool(skill="rea")
def read_function_instructions(
    procedure_or_address: str,
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """Desmonta instruções em assembly via Capstone para uma função ou endereço de memória.

    Args:
        procedure_or_address: Nome do procedimento ou endereço hexadecimal (ex: 'main', '0x140001000').
        offset: Deslocamento inicial de instruções a partir do início da função (padrão: 0).
        limit: Quantidade de instruções assembly a desmontar (padrão: 50).
    """
    return disassemble_window(
        session=active_session,
        target=procedure_or_address,
        instruction_offset=offset,
        limit=limit,
    )


@server.tool()
@skill_tool(skill="rea")
def get_call_graph(procedure_or_address: str, depth: int = 1) -> dict[str, Any]:
    """Reconstrói o grafo de chamadas (funções chamadoras e chamadas) de um procedimento.

    Args:
        procedure_or_address: Nome do procedimento ou endereço de memória alvo.
        depth: Profundidade máxima de exploração da árvore de chamadas (padrão: 1).
    """
    return build_call_graph(
        session=active_session,
        target=procedure_or_address,
        depth=depth,
    )


@server.tool()
@skill_tool(skill="rea")
def procedure_pseudo_code(procedure_or_address: str) -> dict[str, Any]:
    """Gera pseudocódigo descompilado de alto nível em estilo C para um procedimento.

    Args:
        procedure_or_address: Nome do procedimento ou endereço alvo para descompilação.
    """
    return generate_pseudocode(
        session=active_session,
        target=procedure_or_address,
    )


@server.tool()
@skill_tool(skill="rea")
def find_xrefs_to_name(target_name: str, max_results: int = 50) -> dict[str, Any]:
    """Localiza todas as referências cruzadas (XREFs) para uma função, API ou string no binário.

    Args:
        target_name: Nome do procedimento, símbolo importado ou string alvo.
        max_results: Limite máximo de referências cruzadas a retornar (padrão: 50).
    """
    return _find_xrefs_to_name(
        session=active_session,
        target_name=target_name,
        max_results=max_results,
    )


@server.tool()
@skill_tool(skill="rea")
def detect_framework(target_path: str) -> dict[str, Any]:
    """Detecta stack tecnológica, runtime e compilador da aplicação (Electron, .NET, Go, Rust, etc.).

    Args:
        target_path: Caminho do arquivo executável ou diretório da aplicação a ser analisado.
    """
    return _detect_framework(target_path)


@server.tool()
@skill_tool(skill="rea")
def inspect_electron_asar(
    asar_path: str,
    output_dir: str | None = None,
    filter_pattern: str | None = None,
) -> dict[str, Any]:
    """Inspeciona ou extrai pacotes compactados Electron ASAR para recuperar arquivos JavaScript e mapas.

    Args:
        asar_path: Caminho do arquivo .asar da aplicação Electron.
        output_dir: Diretório de destino opcional para extrair os arquivos do pacote.
        filter_pattern: Padrão opcional de filtro de arquivos a inspecionar ou extrair.
    """
    if output_dir:
        return extract_asar_archive(
            asar_path_str=asar_path,
            output_dir_str=output_dir,
            filter_pattern=filter_pattern,
        )
    return inspect_asar(asar_path)


@server.tool()
@skill_tool(skill="rea")
def inspect_dotnet(file_path: str | None = None) -> dict[str, Any]:
    """Inspeciona assemblies compilados .NET (PE gerenciado), metadados CLI e User Strings (#US).

    Args:
        file_path: Caminho opcional do assembly .exe ou .dll .NET (se omitido, usa a sessão ativa).
    """
    target = file_path or (str(active_session.file_path) if active_session.file_path else None)
    if not target:
        return {"error": "Nenhum binário especificado e nenhuma sessão ativa. Execute 'open_binary' primeiro."}
    return inspect_dotnet_assembly(target)


@server.tool()
@skill_tool(skill="rea")
def rea_doctor() -> dict[str, Any]:
    """Executa diagnóstico do ecossistema de engenharia reversa e verifica ferramentas instaladas."""
    ghidra_info = check_ghidra_status()
    return {
        "status": "operational",
        "engine": "REA-Equivalent Agentic Reverse Engineering Suite",
        "fast_path_disassembly": "Capstone Engine v5.0 (Ativo)",
        "supported_architectures": ["x86 (32-bit)", "x64 (AMD64)", "ARM", "ARM64"],
        "supported_formats": ["PE (Windows EXE/DLL)", "ELF (Linux)", "Mach-O (macOS)", "Electron ASAR", ".NET CLI"],
        "ghidra_headless": ghidra_info,
    }


# ============================================================================
# SKILL: DEFENSIVE SECURITY AUDIT & HYGIENE (FuzzingLabs / Gitleaks / Trivy SAST)
# ============================================================================

@server.tool()
@skill_tool(skill="security_audit")
def scan_secrets(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Varre arquivos ou diretórios em busca de chaves de API, tokens e senhas vazadas (estilo Gitleaks).

    Detecta chaves AWS, tokens do GitHub, credenciais Google Cloud, webhooks Slack/Discord,
    chaves privadas RSA e credenciais de alta entropia com ofuscação segura.

    Args:
        target_path: Caminho do arquivo ou diretório a ser auditado contra vazamentos.
        max_findings: Quantidade máxima de achados a retornar (padrão: 100).
    """
    return _scan_secrets(target_path=target_path, max_findings=max_findings)


@server.tool()
@skill_tool(skill="security_audit")
def audit_dependencies(target_path: str) -> dict[str, Any]:
    """Audita dependências do projeto em busca de vulnerabilidades e CVEs conhecidas via OSV.dev (estilo Trivy).

    Analisa manifestos requirements.txt, package.json e pyproject.toml consultando a base de dados
    aberta de vulnerabilidades OSV.dev da OpenSSF/Google.

    Args:
        target_path: Caminho do diretório do projeto ou arquivo de manifesto a auditar.
    """
    return _audit_dependencies(target_path=target_path)


@server.tool()
@skill_tool(skill="security_audit")
def run_sast_scan(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Executa análise estática de segurança de código (SAST) em busca de padrões de código inseguros.

    Detecta injeção de comandos, desserialização insegura (Pickle/YAML), execução dinâmica (eval/exec),
    concatenação insegura em consultas SQL, criptografia fraca e falhas de DOM XSS.

    Args:
        target_path: Caminho do arquivo fonte ou diretório do repositório para analisar.
        max_findings: Quantidade máxima de vulnerabilidades a retornar (padrão: 100).
    """
    return _run_sast_scan(target_path=target_path, max_findings=max_findings)


# ============================================================================
# SKILL: PASSIVE RECONNAISSANCE & SURFACE POSTURE (OSINT)
# ============================================================================

@server.tool()
@skill_tool(skill="osint_recon")
def inspect_http_headers(
    url: str,
    use_tor: bool = False,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Inspeciona cabeçalhos de segurança HTTP e identifica proteções de navegador ausentes ou vazamento de banners.

    Avalia HSTS, Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy
    e sinaliza vazamento de banners do servidor (Server, X-Powered-By).
    Suporta tráfego camuflado via modo stealth / nó Tor Onion.

    Args:
        url: URL web ou domínio alvo (ex: 'https://exemplo.com').
        use_tor: Forçar roteamento pelo nó Tor SOCKS5 mesmo com stealth global inativo (padrão: False).
        proxy: URL customizada de proxy SOCKS5/HTTP (ex: 'socks5://127.0.0.1:9050').
    """
    return _inspect_http_headers(target_url=url, use_tor=use_tor, proxy=proxy)


@server.tool()
@skill_tool(skill="osint_recon")
def inspect_tls_certificate(hostname: str, port: int = 443) -> dict[str, Any]:
    """Inspeciona certificado SSL/TLS verificando validade, expiração, autoridade emissora (CA), SANs e cifras.

    Args:
        hostname: Nome de domínio ou host para inspeção (ex: 'google.com').
        port: Porta TCP do serviço TLS (padrão: 443).
    """
    return _inspect_tls_certificate(hostname=hostname, port=port)


@server.tool()
@skill_tool(skill="osint_recon")
def lookup_dns_records(domain: str) -> dict[str, Any]:
    """Consulta registros DNS e audita postura de proteção contra spoofing de e-mails (SPF e DMARC).

    Args:
        domain: Nome do domínio alvo para consulta (ex: 'cloudflare.com').
    """
    return _lookup_dns_records(domain=domain)


@server.tool()
@skill_tool(skill="osint_recon")
def search_username_maigret(
    username: str,
    top_sites: int = 50,
    tags: str | None = None,
    site: str | None = None,
    timeout: int = 15,
    no_extracting: bool = False,
    keep_report: bool = True,
    use_tor: bool = False,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Investiga perfis públicos e presença de um nome de usuário em mais de 3.000 sites via Maigret OSINT.

    Varre sites públicos, redes sociais, fóruns e redes de desenvolvedores para revelar pegadas digitais,
    perfis reivindicados, fotos de avatar, nomes completos e métricas de seguidores.
    Suporta camuflagem de tráfego via nós Tor Onion para prevenir rastreamento de IP ou bloqueios.

    Args:
        username: Nome de usuário alvo para investigar (ex: 'octocat', 'torvalds').
        top_sites: Quantidade de sites mais populares para verificar por ranking Alexa (padrão: 50).
        tags: Categorias/tags opcionais separadas por vírgula para filtrar sites (ex: 'coding,social,tech').
        site: Nome de site específico ou lista separada por vírgula (ex: 'GitHub,Reddit,Twitter').
        timeout: Tempo limite em segundos por requisição HTTP para cada site (padrão: 15).
        no_extracting: Desativar extração de dados estendidos (avatares, bio, contagem de seguidores).
        keep_report: Salvar cópia do dossiê JSON gerado na pasta reports/ (padrão: True).
        use_tor: Forçar roteamento pelo nó Tor SOCKS5 mesmo com stealth global inativo (padrão: False).
        proxy: URL de proxy alternativa ou endereço de nó Tor (ex: 'socks5://127.0.0.1:9050').
    """
    return _search_username_maigret(
        username=username,
        top_sites=top_sites,
        tags=tags,
        site=site,
        timeout=timeout,
        no_extracting=no_extracting,
        keep_report=keep_report,
        use_tor=use_tor,
        proxy=proxy,
    )


@server.tool()
@skill_tool(skill="osint_recon")
def configure_stealth_mode(
    enabled: bool = True,
    proxy_url: str = "socks5://127.0.0.1:9050",
    dns_over_tor: bool = True,
) -> dict[str, Any]:
    """Ativa ou desativa o Modo Stealth e configura nós Onion (Tor) para camuflar o tráfego de rede.

    Quando ativado, todas as requisições de coleta de dados, reconhecimento e OSINT são roteadas
    através de um proxy Tor / SOCKS5h com resolução DNS remota, mascarando a identidade e o IP do operador.

    Args:
        enabled: Ativar (True) ou desativar (False) o Modo Stealth globalmente (padrão: True).
        proxy_url: Endereço do gateway Tor SOCKS5 (ex: 'socks5://127.0.0.1:9050' para daemon Tor ou 'socks5://127.0.0.1:9150' para Tor Browser).
        dns_over_tor: Forçar resolução DNS remota via túnel Tor para blindagem total contra vazamentos DNS (padrão: True).
    """
    return _configure_stealth_mode(enabled=enabled, proxy_url=proxy_url, dns_over_tor=dns_over_tor)


@server.tool()
@skill_tool(skill="osint_recon")
def test_tor_connectivity(
    proxy_url: str = "socks5://127.0.0.1:9050",
    timeout: int = 6,
) -> dict[str, Any]:
    """Testa a conectividade com o nó Onion / proxy Tor e verifica se o IP público foi mascarado com sucesso.

    Realiza verificação de handshake no socket e consulta os endpoints de integridade da rede Tor
    para validar a camuflagem e identificar o IP de saída ativo.

    Args:
        proxy_url: URL do proxy Tor para testar (padrão: 'socks5://127.0.0.1:9050').
        timeout: Tempo limite de verificação em segundos (padrão: 6).
    """
    return _test_tor_connectivity(proxy_url=proxy_url, timeout=float(timeout))


@server.tool()
@skill_tool(skill="osint_recon")
def get_maigret_stats() -> dict[str, Any]:
    """Consulta estatísticas de cobertura, quantidade de sites suportados e métricas da base Maigret OSINT."""
    return _get_maigret_stats()


# ============================================================================
# SKILL: THREAT INTELLIGENCE & MITRE ATT&CK DEFENSE
# ============================================================================

@server.tool()
@skill_tool(skill="threat_intel")
def map_mitre_attack(query: str) -> dict[str, Any]:
    """Mapeia observações de segurança, comandos ou APIs ao framework MITRE ATT&CK Enterprise.

    Retorna táticas, IDs de técnicas oficiais (ex: T1055), descrições de ameaças e mitigações defensivas.

    Args:
        query: Nome da técnica, ID ou palavra-chave de comportamento (ex: 'process injection', 'T1059').
    """
    return _map_mitre_attack(query=query)


@server.tool()
@skill_tool(skill="threat_intel")
def analyze_ioc_indicator(indicator: str) -> dict[str, Any]:
    """Categoriza, valida e aplica neutralização segura (defang) em Indicadores de Comprometimento (IOCs).

    Valida IPv4, IPv6, MD5, SHA-256, URL, domínio ou e-mail, neutralizando-os (ex: 1[.]1[.]1[.]1) para documentação
    segura e sugerindo ações imediatas de threat hunting e contenção.

    Args:
        indicator: String do indicador de comprometimento (ex: '192.168.1.1', 'http://malicious.test').
    """
    return _analyze_ioc_indicator(indicator=indicator)


@server.tool()
@skill_tool(skill="threat_intel")
def lookup_cve_details(cve_id: str) -> dict[str, Any]:
    """Consulta detalhes técnicos, severidade CVSS e avisos de segurança de uma CVE na base aberta OSV.dev.

    Args:
        cve_id: Identificador oficial da CVE (ex: 'CVE-2021-44228', 'CVE-2023-38606').
    """
    return _lookup_cve_details(cve_id=cve_id)


# ============================================================================
# SKILL: CLOUD SECURITY & CONTAINER HARDENING
# ============================================================================

@server.tool()
@skill_tool(skill="cloud_container")
def audit_dockerfile(dockerfile_path_or_content: str) -> dict[str, Any]:
    """Audita Dockerfile contra recomendações de segurança do CIS Container Benchmarks e boas práticas.

    Identifica execução como usuário root, imagens base sem tag de versão fixa, ausência de HEALTHCHECK,
    pipes inseguros (curl | sh) e segredos hardcoded.

    Args:
        dockerfile_path_or_content: Caminho para o Dockerfile ou conteúdo textual do arquivo.
    """
    return _audit_dockerfile(dockerfile_path_or_content=dockerfile_path_or_content)


@server.tool()
@skill_tool(skill="cloud_container")
def audit_iam_policy(policy_json_str: str) -> dict[str, Any]:
    """Audita documentos JSON de políticas IAM (AWS/Cloud) contra wildcards excessivos e escalonamento de privilégios.

    Args:
        policy_json_str: Conteúdo JSON da política IAM ou caminho para arquivo de política.
    """
    return _audit_iam_policy(policy_json_str=policy_json_str)


# ============================================================================
# SKILL: APPLICATION SECURITY & OWASP / LLM AUDIT (Bri Russell Skills)
# ============================================================================

@server.tool()
@skill_tool(skill="appsec")
def audit_owasp_top10(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Audita código-fonte contra os 10 principais riscos de segurança web do OWASP Top 10 (2021).

    Detecta quebra de controle de acesso, falhas criptográficas, injeções (SQL/NoSQL/Command),
    configurações de segurança incorretas e falsificação de requisição do lado do servidor (SSRF).

    Args:
        target_path: Caminho do diretório de código-fonte ou arquivo a ser auditado.
        max_findings: Quantidade máxima de vulnerabilidades a retornar (padrão: 100).
    """
    return _audit_owasp_top10(target_path=target_path, max_findings=max_findings)


@server.tool()
@skill_tool(skill="appsec")
def audit_api_security(target_path: str, max_findings: int = 100) -> dict[str, Any]:
    """Audita rotas e endpoints de APIs REST e GraphQL contra o OWASP API Security Top 10.

    Detecta padrões de BOLA/IDOR, risco de atribuição em massa (mass assignment) e CORS permissivo com wildcard.

    Args:
        target_path: Caminho do diretório do código da API ou arquivo de rotas.
        max_findings: Quantidade máxima de vulnerabilidades a retornar (padrão: 100).
    """
    return _audit_api_security(target_path=target_path, max_findings=max_findings)


@server.tool()
@skill_tool(skill="appsec")
def audit_prompt_injection(target_path: str, max_findings: int = 50) -> dict[str, Any]:
    """Audita código de aplicações de IA e LLM contra injeção de prompt e riscos de execução.

    Verifica vulnerabilidades do OWASP Top 10 para LLMs: concatenação insegura de prompts, sinks de execução
    sem validação (eval/exec) e geração dinâmica de consultas SQL.

    Args:
        target_path: Caminho do arquivo ou diretório da aplicação de IA/LLM.
        max_findings: Quantidade máxima de achados a retornar (padrão: 50).
    """
    return _audit_prompt_injection(target_path=target_path, max_findings=max_findings)


# ============================================================================
# SKILL: DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR / NIST SP 800-61r2)
# ============================================================================

@server.tool()
@skill_tool(skill="incident_response")
def triage_security_incident(
    incident_description: str,
    affected_assets: list[str] | str,
    observed_iocs: list[str] | str | None = None,
    data_exfiltration_suspected: bool = False,
) -> dict[str, Any]:
    """Executa triagem estruturada de incidentes, classificação de severidade e planejamento de contenção (NIST).

    Segue as diretrizes do framework NIST SP 800-61r2, produzindo classificação de severidade (P1 a P4),
    ações de contenção imediata e checklist de preservação de evidências.

    Args:
        incident_description: Resumo detalhado da atividade anômala ou violação observada.
        affected_assets: Nomes de host, endereços IP ou serviços comprometidos.
        observed_iocs: Lista de indicadores de comprometimento suspeitos (hashes, IPs, domínios).
        data_exfiltration_suspected: Indica se há suspeita de exfiltração de dados confidenciais.
    """
    return _triage_security_incident(
        incident_description=incident_description,
        affected_assets=affected_assets,
        observed_iocs=observed_iocs,
        data_exfiltration_suspected=data_exfiltration_suspected,
    )


@server.tool()
@skill_tool(skill="incident_response")
def generate_incident_comms(
    incident_id: str,
    incident_summary: str,
    current_status: str = "Contained",
    audience: str = "technical",
) -> dict[str, Any]:
    """Gera comunicados profissionais de incidentes de segurança adaptados por público-alvo (Executivo, Técnico, Cliente).

    Args:
        incident_id: Código identificador do incidente (ex: 'INC-2026-0042').
        incident_summary: Resumo executivo ou técnico do evento e ações tomadas.
        current_status: Status atual do incidente (ex: 'Investigando', 'Contido', 'Resolvido').
        audience: Público-alvo da comunicação: 'executive', 'technical' ou 'customer'.
    """
    return _generate_incident_comms(
        incident_id=incident_id,
        incident_summary=incident_summary,
        current_status=current_status,
        audience=audience,
    )


def main() -> None:
    """Run MCP server over standard I/O."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
