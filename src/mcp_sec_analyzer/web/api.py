"""REST and Web API Backend for Unified Cybersecurity MCP Hub."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import time
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from ..core.memory import unified_memory
from ..core.stealth import (
    configure_stealth_mode as _configure_stealth_mode,
    is_stealth_active,
    load_stealth_config,
    test_tor_connection as _test_tor_connection,
)
from ..server import server
from ..skills.memory_skill import (
    clear_memory as _clear_memory,
    export_investigation_report as _export_investigation_report,
    get_timeline as _get_timeline,
    recall as _recall,
    remember as _remember,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"

SKILL_CATALOG = {
    "memory": {
        "id": "memory",
        "name": "Memória & Contexto Universal",
        "icon": "🧠",
        "badge": "Motor de Memória",
        "description": "Estado persistente de investigação em SQLite, histórico de ações, notas e gerador de relatórios.",
        "color": "#a1a1aa",
    },
    "osint_recon": {
        "id": "osint_recon",
        "name": "OSINT & Superfície (Maigret)",
        "icon": "🔍",
        "badge": "OSINT Ativo",
        "description": "Investigação de pegada digital Maigret em mais de 3.000 sites, certificados SSL/TLS, cabeçalhos HTTP e DNS.",
        "color": "#f43f5e",
    },
    "rea": {
        "id": "rea",
        "name": "Engenharia Reversa (REA Toolkit)",
        "icon": "⚙️",
        "badge": "Triage Binária",
        "description": "Desmontagem de binários (PE/ELF), grafos de chamadas, descompilação C, strings e análise Electron/NET.",
        "color": "#cbd5e1",
    },
    "security_audit": {
        "id": "security_audit",
        "name": "Auditoria de Código & SAST",
        "icon": "🛡️",
        "badge": "Defesa de Código",
        "description": "Detecção de segredos (regras Gitleaks), scanner de vulnerabilidades OSV.dev e análise estática SAST.",
        "color": "#e11d48",
    },
    "appsec": {
        "id": "appsec",
        "name": "AppSec, OWASP & LLMs",
        "icon": "🌐",
        "badge": "OWASP / LLM",
        "description": "Auditoria de código contra OWASP Top 10, OWASP API Security e salvaguardas de injeção de prompt em IA.",
        "color": "#fb7185",
    },
    "threat_intel": {
        "id": "threat_intel",
        "name": "Threat Intel & MITRE ATT&CK",
        "icon": "🎯",
        "badge": "TTPs & IOCs",
        "description": "Mapeamento ao MITRE ATT&CK Enterprise, validação/defang de IOCs e consulta de vulnerabilidades CVE.",
        "color": "#ff4d6d",
    },
    "cloud_container": {
        "id": "cloud_container",
        "name": "Segurança em Nuvem & Containers",
        "icon": "☁️",
        "badge": "Hardening Cloud",
        "description": "Conformidade de Dockerfiles com CIS Benchmarks e análise de privilégio mínimo em políticas IAM.",
        "color": "#94a3b8",
    },
    "incident_response": {
        "id": "incident_response",
        "name": "Resposta a Incidentes (DFIR)",
        "icon": "🚨",
        "badge": "DFIR / NIST",
        "description": "Triagem rápida P1-P4 (NIST SP 800-61r2), playbooks de contenção e comunicados formais por audiência.",
        "color": "#ef4444",
    },
    "general": {
        "id": "general",
        "name": "Serviços do Sistema",
        "icon": "⚡",
        "badge": "Meta Core",
        "description": "Status de saúde do servidor, catálogo de habilidades e capacidades da plataforma.",
        "color": "#64748b",
    },
}

TOOL_SKILL_MAP = {
    # memory
    "remember": "memory",
    "recall": "memory",
    "get_timeline": "memory",
    "export_investigation_report": "memory",
    "clear_memory": "memory",
    # rea
    "open_binary": "rea",
    "binary_overview": "rea",
    "search_strings": "rea",
    "list_procedures": "rea",
    "read_function_instructions": "rea",
    "get_call_graph": "rea",
    "procedure_pseudo_code": "rea",
    "find_xrefs_to_name": "rea",
    "detect_framework": "rea",
    "inspect_electron_asar": "rea",
    "inspect_dotnet": "rea",
    "rea_doctor": "rea",
    # security_audit
    "scan_secrets": "security_audit",
    "audit_dependencies": "security_audit",
    "run_sast_scan": "security_audit",
    # appsec
    "audit_owasp_top10": "appsec",
    "audit_api_security": "appsec",
    "audit_prompt_injection": "appsec",
    # osint_recon
    "inspect_http_headers": "osint_recon",
    "inspect_tls_certificate": "osint_recon",
    "lookup_dns_records": "osint_recon",
    "search_username_maigret": "osint_recon",
    "get_maigret_stats": "osint_recon",
    "configure_stealth_mode": "osint_recon",
    "test_tor_connectivity": "osint_recon",
    # threat_intel
    "map_mitre_attack": "threat_intel",
    "analyze_ioc_indicator": "threat_intel",
    "lookup_cve_details": "threat_intel",
    # cloud_container
    "audit_dockerfile": "cloud_container",
    "audit_iam_policy": "cloud_container",
    # incident_response
    "triage_security_incident": "incident_response",
    "generate_incident_comms": "incident_response",
    # general
    "list_skills": "general",
}

# Example payloads for 1-click test fill
TOOL_EXAMPLES = {
    "configure_stealth_mode": {
        "enabled": True,
        "proxy_url": "socks5://127.0.0.1:9050",
        "dns_over_tor": True,
    },
    "test_tor_connectivity": {
        "proxy_url": "socks5://127.0.0.1:9050",
        "timeout": 6,
    },
    "search_username_maigret": {
        "username": "octocat",
        "top_sites": 20,
        "site": "GitHub,Reddit",
        "timeout": 10,
        "use_tor": False,
    },
    "get_maigret_stats": {},
    "inspect_http_headers": {
        "url": "https://github.com",
        "use_tor": False,
    },
    "inspect_tls_certificate": {
        "hostname": "google.com",
        "port": 443,
    },
    "lookup_dns_records": {
        "domain": "cloudflare.com",
    },
    "map_mitre_attack": {
        "query": "process injection",
    },
    "analyze_ioc_indicator": {
        "indicator": "http://evil-c2.example.com/payload.exe",
    },
    "lookup_cve_details": {
        "cve_id": "CVE-2021-44228",
    },
    "audit_dockerfile": {
        "dockerfile_path_or_content": "FROM python:3.9\nUSER root\nRUN curl http://untrusted.sh | sh\nEXPOSE 22\nCMD [\"python\", \"app.py\"]",
    },
    "audit_iam_policy": {
        "policy_json_str": json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }, indent=2),
    },
    "audit_owasp_top10": {
        "target_path": "src",
        "max_findings": 10,
    },
    "audit_api_security": {
        "target_path": "src",
        "max_findings": 10,
    },
    "audit_prompt_injection": {
        "prompt_template": "Translate the following user input into French: {user_input}",
        "allow_system_override": False,
    },
    "scan_secrets": {
        "target_path": "src",
        "max_findings": 10,
    },
    "audit_dependencies": {
        "dependency_file_path": "pyproject.toml",
    },
    "run_sast_scan": {
        "target_path": "src",
        "max_findings": 10,
    },
    "triage_security_incident": {
        "incident_description": "Multiple unauthorized SSH attempts detected from external IP, followed by modified authorized_keys file on bastion host.",
        "affected_assets": ["bastion.prod.internal", "jumpbox-01"],
        "observed_iocs": ["198.51.100.44", "/root/.ssh/authorized_keys"],
    },
    "generate_incident_comms": {
        "incident_id": "INC-2026-042",
        "incident_summary": "Attempted SSH brute-force and key modification stopped and bastion rebuilt.",
        "audience": "executive",
    },
    "remember": {
        "title": "Suspicious recon from 198.51.100.44",
        "content": "Observed port scanning and SSH probing against bastion. IP reported to abuse.",
        "category": "finding",
        "tags": ["recon", "external_ip", "threat"],
        "skill": "threat_intel",
    },
    "recall": {
        "query": "",
        "limit": 20,
    },
    "get_timeline": {
        "limit": 25,
    },
    "export_investigation_report": {},
    "rea_doctor": {},
    "detect_framework": {
        "target_file_or_dir": "src",
    },
    "list_skills": {},
}


TOOL_DESCRIPTIONS_PT = {
    "configure_stealth_mode": {
        "short": "Ativa ou desativa o Modo Stealth e camufla o tráfego via nós Onion (Tor).",
        "full": "Ativa ou desativa o Modo Stealth globalmente e configura o roteamento através de gateways SOCKS5 / nós Tor Onion (ex: porta 9050 ou 9150). Quando ativo, todas as conexões de reconhecimento, scraping e OSINT têm seu tráfego e DNS tunelados, ocultando completamente o IP de origem do pesquisador.",
        "params": {
            "enabled": "Ativar (true) ou desativar (false) o Modo Stealth globalmente.",
            "proxy_url": "Endereço do gateway Tor SOCKS5 (padrão: 'socks5://127.0.0.1:9050' para Tor daemon ou 'socks5://127.0.0.1:9150' para Tor Browser).",
            "dns_over_tor": "Encaminhar requisições DNS através do túnel Tor (socks5h) para blindagem contra vazamento de DNS.",
        },
    },
    "test_tor_connectivity": {
        "short": "Testa conectividade com o nó Onion/Tor e valida o IP público camuflado.",
        "full": "Verifica se o serviço Tor está acessível localmente e consulta a API de verificação oficial do projeto Tor para atestar que o tráfego está de fato passando pela rede Onion e obter o IP de saída ativo mascarado.",
        "params": {
            "proxy_url": "Endereço do proxy Tor para testar (padrão: 'socks5://127.0.0.1:9050').",
            "timeout": "Tempo limite em segundos para o teste de conectividade (padrão: 6).",
        },
    },
    "search_username_maigret": {
        "short": "Investiga pegada digital e perfis de um usuário em mais de 3.000 sites e redes.",
        "full": "Investiga a presença e perfis públicos associados a um nome de usuário em mais de 3.000 sites, redes sociais e plataformas técnicas via Maigret OSINT. Extrai avatares, biografia, contagem de seguidores, data de criação e links diretos. Suporta tráfego camuflado via Tor.",
        "params": {
            "username": "Nome de usuário alvo para investigar (ex: 'octocat', 'torvalds').",
            "top_sites": "Quantidade de sites mais populares para verificar por ranking Alexa (padrão: 50).",
            "tags": "Filtrar sites por categorias separadas por vírgula (ex: 'coding,social,tech').",
            "site": "Nomes específicos de sites separados por vírgula (ex: 'GitHub,Reddit,Twitter').",
            "timeout": "Tempo limite em segundos por requisição HTTP (padrão: 15).",
            "no_extracting": "Desativar extração de detalhes estendidos (avatares, bio, contagem de seguidores).",
            "keep_report": "Salvar cópia persistente do relatório JSON na pasta reports/ (padrão: True).",
            "use_tor": "Forçar roteamento pelo nó Tor SOCKS5 mesmo com stealth global inativo.",
            "proxy": "URL customizada de proxy alternativo (ex: 'socks5://127.0.0.1:9050').",
        },
    },
    "get_maigret_stats": {
        "short": "Exibe estatísticas de cobertura e categorias da base de dados Maigret OSINT.",
        "full": "Consulta a base de dados local do Maigret e retorna métricas de cobertura, número total de plataformas suportadas (3.000+ sites) e distribuição de categorias e tags.",
        "params": {},
    },
    "inspect_http_headers": {
        "short": "Analisa cabeçalhos HTTP de segurança (HSTS, CSP, etc.) e vazamentos de versão.",
        "full": "Audita cabeçalhos de resposta HTTP para verificar a presença de proteções modernas de navegador (HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) e identifica vazamentos de banners do servidor (Server, X-Powered-By). Suporta camuflagem via Tor.",
        "params": {
            "url": "URL web ou domínio alvo para inspeção (ex: 'https://exemplo.com').",
            "use_tor": "Forçar roteamento pelo nó Tor SOCKS5 mesmo com stealth global inativo.",
            "proxy": "URL customizada de proxy alternativo (ex: 'socks5://127.0.0.1:9050').",
        },
    },
    "inspect_tls_certificate": {
        "short": "Verifica validade, emissor, SANs e cifras do certificado SSL/TLS.",
        "full": "Inspeciona o certificado SSL/TLS de um host remoto, calculando dias até expiração, cadeia de confiança (CA emissora), nomes alternativos (SANs), versão do protocolo TLS negociado e cifras criptográficas suportadas.",
        "params": {
            "hostname": "Domínio ou host a inspecionar (ex: 'google.com').",
            "port": "Porta TCP do serviço TLS (padrão: 443).",
        },
    },
    "lookup_dns_records": {
        "short": "Consulta registros DNS e avalia postura anti-spoofing (SPF e DMARC).",
        "full": "Resolve registros DNS (A, AAAA, MX, TXT, NS, CNAME) e audita a postura de proteção contra personificação e spoofing de e-mails, validando se as políticas SPF e DMARC estão devidamente configuradas e ativas.",
        "params": {
            "domain": "Nome do domínio para consulta (ex: 'cloudflare.com').",
        },
    },
    "audit_owasp_top10": {
        "short": "Audita código-fonte contra vulnerabilidades web do OWASP Top 10 (2021).",
        "full": "Varre o código-fonte em busca de falhas críticas descritas no OWASP Top 10 (2021): quebra de controle de acesso, falhas criptográficas, injeções (SQL/Comando), configurações incorretas e falsificação de requisição do lado do servidor (SSRF).",
        "params": {
            "target_path": "Caminho do diretório de código-fonte ou arquivo a ser auditado.",
            "max_findings": "Limite máximo de vulnerabilidades a retornar (padrão: 100).",
        },
    },
    "audit_api_security": {
        "short": "Audita rotas e endpoints contra o OWASP API Security Top 10 (2023).",
        "full": "Inspeciona controladores e rotas de APIs REST e GraphQL contra os riscos do OWASP API Security Top 10: quebra de autorização no nível de objeto (BOLA), quebra de autenticação, consumo irrestrito de recursos (rate limit) e quebra de autorização no nível de função (BFLA).",
        "params": {
            "target_path": "Caminho do diretório ou arquivo de rotas da API para auditar.",
            "max_findings": "Limite máximo de achados a retornar (padrão: 100).",
        },
    },
    "audit_prompt_injection": {
        "short": "Verifica vulnerabilidades de Prompt Injection e jailbreaks em prompts de LLM.",
        "full": "Analisa templates de prompt e fluxos de IA generativa/LLMs contra injeções diretas e indiretas de prompt, tentativas de substituição de instruções de sistema (system prompt override) e vazamento de contexto seguro.",
        "params": {
            "target_path": "Caminho do arquivo ou diretório da aplicação de IA/LLM.",
            "max_findings": "Limite máximo de achados a retornar (padrão: 50).",
        },
    },
    "scan_secrets": {
        "short": "Detecta chaves de API, senhas, tokens e credenciais expostas no código.",
        "full": "Executa varredura profunda com padrões estilo Gitleaks para identificar chaves privadas RSA/SSH, senhas hardcoded, tokens de nuvem (AWS, GCP, Azure), chaves do GitHub e credenciais de API em arquivos locais.",
        "params": {
            "target_path": "Caminho do diretório ou arquivo onde buscar segredos vazados.",
            "max_findings": "Número máximo de segredos a retornar (padrão: 100).",
        },
    },
    "audit_dependencies": {
        "short": "Verifica vulnerabilidades conhecidas (CVEs) em dependências via OSV.dev.",
        "full": "Inspeciona manifestos de dependências (pyproject.toml, requirements.txt, package.json, etc.) e consulta a base global de vulnerabilidades de código aberto OSV.dev (Google/OpenSSF) para apontar CVEs ativas.",
        "params": {
            "target_path": "Caminho do diretório do projeto ou arquivo de manifesto de dependências a ser analisado.",
        },
    },
    "run_sast_scan": {
        "short": "Executa análise estática de código (SAST) em busca de padrões perigosos.",
        "full": "Analisa a Árvore de Sintaxe Abstrata (AST) do código-fonte procurando sinks vulneráveis: execução dinâmica (eval, exec), injeção de comandos de sistema operacional, desserialização insegura de objetos e chamadas perigosas.",
        "params": {
            "target_path": "Caminho do arquivo ou diretório para análise estática SAST.",
            "max_findings": "Limite máximo de achados a retornar (padrão: 100).",
        },
    },
    "map_mitre_attack": {
        "short": "Mapeia comportamentos ou táticas ao framework MITRE ATT&CK Enterprise.",
        "full": "Correlaciona comandos, APIs, comportamentos suspeitos ou logs com a base oficial de técnicas, táticas e procedimentos (TTPs) do MITRE ATT&CK Enterprise, fornecendo IDs oficiais (ex: T1055) e mitigações defensivas.",
        "params": {
            "query": "Termo de busca, nome de técnica, comportamento ou API (ex: 'process injection', 'T1059').",
        },
    },
    "analyze_ioc_indicator": {
        "short": "Classifica e aplica defanging seguro em IOCs (URLs, IPs, hashes).",
        "full": "Identifica o tipo de Indicador de Comprometimento (URL, endereço IPv4/IPv6, domínio, hash MD5/SHA256) e gera a versão neutralizada (defanged, ex: hxxp://, 1[.]1[.]1[.]1) para compartilhamento seguro em relatórios.",
        "params": {
            "indicator": "Indicador de comprometimento a ser classificado e neutralizado (ex: '192.168.1.1', 'http://malicious.test').",
        },
    },
    "lookup_cve_details": {
        "short": "Consulta descrição, severidade CVSS e impacto de vulnerabilidades CVE.",
        "full": "Busca detalhes técnicos de uma vulnerabilidade específica (ex: CVE-2021-44228) junto às bases de vulnerabilidades de segurança OSV.dev, retornando descrição, pontuação CVSS e referências de mitigação.",
        "params": {
            "cve_id": "Identificador oficial da vulnerabilidade no formato CVE-AAAA-NNNNN (ex: 'CVE-2021-44228').",
        },
    },
    "audit_dockerfile": {
        "short": "Audita Dockerfiles contra recomendações e benchmarks do CIS Docker.",
        "full": "Verifica arquivos Dockerfile em busca de violações de segurança e boas práticas: execução como usuário root, uso da tag :latest, exposição de portas sensíveis (SSH 22), comandos inseguros (curl | sh) e ausência de healthchecks.",
        "params": {
            "dockerfile_path_or_content": "Caminho para o Dockerfile ou conteúdo textual do arquivo para validação.",
        },
    },
    "audit_iam_policy": {
        "short": "Audita políticas IAM em JSON contra privilégios excessivos e escalonamento.",
        "full": "Inspeciona políticas de controle de acesso (IAM) em nuvem para identificar wildcards perigosos (Action: *, Resource: *), permissões administrativas desnecessárias e caminhos potenciais de escalonamento de privilégios.",
        "params": {
            "policy_json_str": "Documento JSON da política IAM ou caminho para arquivo de política.",
        },
    },
    "triage_security_incident": {
        "short": "Realiza triagem estruturada de incidentes e gera plano de contenção (NIST).",
        "full": "Executa triagem rápida de incidentes de segurança com classificação de severidade (P1-Crítico a P4-Baixo) segundo o ciclo de vida NIST SP 800-61r2. Gera playbook de contenção imediata, cadeia de custódia e orientações de preservação de evidências.",
        "params": {
            "incident_description": "Descrição detalhada dos fatos e evidências observadas no incidente.",
            "affected_assets": "Lista de ativos, servidores, nós ou contas afetadas.",
            "observed_iocs": "Indicadores de comprometimento (IPs, hashes, arquivos) observados.",
            "data_exfiltration_suspected": "Indica se há suspeita de exfiltração de dados confidenciais (padrão: False).",
        },
    },
    "generate_incident_comms": {
        "short": "Gera comunicados e notificações de incidentes sob medida por público.",
        "full": "Redige comunicados profissionais de resposta a incidentes formatados de acordo com o público-alvo: Executivo (C-level e diretoria), Técnico (equipes SOC/Engenharia) ou Clientes/Regulatório, garantindo clareza e conformidade.",
        "params": {
            "incident_id": "Código identificador do incidente (ex: 'INC-2026-0042').",
            "incident_summary": "Resumo executivo ou técnico da ocorrência, impacto e ações tomadas.",
            "current_status": "Status atual do ciclo de vida do incidente ('Investigating', 'Contained', 'Resolved').",
            "audience": "Público-alvo do comunicado ('executive', 'technical', ou 'customer').",
        },
    },
    "remember": {
        "short": "Salva uma descoberta, anotação ou hipótese na memória SQLite permanente.",
        "full": "Armazena uma observação, insight técnico, hipótese de ameaça, IOC ou nota na base universal de memória da investigação (.mcp_memory/unified_memory.db), preservando o contexto entre sessões.",
        "params": {
            "title": "Título descritivo da descoberta ou nota.",
            "content": "Conteúdo detalhado, evidências observadas ou contexto.",
            "category": "Categoria da anotação ('finding', 'hypothesis', 'ioc', 'vulnerability', 'note').",
            "tags": "Tags ou marcadores associados (separados por vírgula ou lista).",
            "skill": "Habilidade de segurança relacionada à anotação.",
            "target_ref": "Referência do alvo ou ativo investigado.",
        },
    },
    "recall": {
        "short": "Pesquisa e recupera descobertas e anotações gravadas na memória universal.",
        "full": "Realiza buscas estruturadas por termo, tag, habilidade ou categoria na base SQLite de memória da investigação, recuperando achados anteriores.",
        "params": {
            "query": "Termo ou palavra-chave para buscar no título e conteúdo.",
            "skill": "Filtrar por habilidade específica (opcional).",
            "tag": "Filtrar por tag específica (opcional).",
            "category": "Filtrar por categoria específica (opcional).",
            "limit": "Quantidade máxima de registros a retornar (padrão: 20).",
        },
    },
    "get_timeline": {
        "short": "Recupera o histórico cronológico de todas as ações executadas no hub.",
        "full": "Retorna a linha do tempo cronológica com registro auditado de todas as ferramentas chamadas, parâmetros utilizados, durações e resumos das ações executadas em qualquer habilidade.",
        "params": {
            "skill": "Filtrar eventos por habilidade específica (opcional).",
            "limit": "Número máximo de eventos recentes a recuperar (padrão: 50).",
        },
    },
    "export_investigation_report": {
        "short": "Gera e exporta relatório e dossiê completo de investigação em Markdown.",
        "full": "Compila todas as descobertas registradas, timeline de atividades e achados técnicos em um relatório formal em formato Markdown pronto para exportação.",
        "params": {
            "skill": "Filtrar dossiê por habilidade específica (opcional).",
        },
    },
    "clear_memory": {
        "short": "Limpa todos os registros de memória e histórico da investigação atual.",
        "full": "Exclui com segurança as anotações, histórico e timeline gravados na base SQLite de memória da investigação (requer confirmação explícita).",
        "params": {
            "confirm": "Confirmação obrigatória para resetar a memória (deve ser True).",
            "skill": "Habilidade específica cujos dados devem ser apagados (opcional).",
        },
    },
    "open_binary": {
        "short": "Carrega e inicializa um executável binário (PE/ELF) para engenharia reversa.",
        "full": "Abre e prepara um arquivo executável para análise estática e triage com o toolkit REA, detectando arquitetura, formato e seções.",
        "params": {
            "file_path": "Caminho do arquivo binário (PE, ELF ou Mach-O) para análise.",
        },
    },
    "binary_overview": {
        "short": "Visão geral do binário: arquitetura, seções, hashes e proteções (DEP/ASLR).",
        "full": "Examina cabeçalhos PE/ELF do binário em sessão, calculando hashes (MD5, SHA256), entropia de seções e identificando mitigações de segurança ativas (DEP/NX, ASLR, SafeSEH, CFG).",
        "params": {
            "file_path": "Caminho opcional do arquivo binário (se omitido, usa a sessão ativa).",
        },
    },
    "search_strings": {
        "short": "Extrai e filtra strings legíveis (ASCII/Unicode) do binário em análise.",
        "full": "Varre o binário em busca de strings de texto legíveis (ASCII e UTF-16), permitindo filtragem por tamanho mínimo, expressões regulares e termos de busca (ex: URLs, caminhos de arquivo, APIs).",
        "params": {
            "query": "Termo de busca textual para filtrar as strings encontradas.",
            "category": "Categoria de strings ('all', 'urls', 'paths', 'registry', 'crypto').",
            "min_length": "Comprimento mínimo de caracteres da string (padrão: 5).",
            "max_results": "Limite máximo de resultados retornados (padrão: 100).",
            "file_path": "Caminho opcional do binário (se omitido, usa a sessão ativa).",
        },
    },
    "list_procedures": {
        "short": "Lista funções, procedimentos e símbolos exportados/importados no binário.",
        "full": "Enumera as funções detectadas, endereços de entrada, símbolos exportados e tabelas de importação (IAT) do arquivo binário carregado.",
        "params": {
            "filter_name": "Filtro textual opcional para o nome da função ou procedimento.",
            "limit": "Limite máximo de procedimentos a retornar (padrão: 100).",
        },
    },
    "read_function_instructions": {
        "short": "Desmonta instruções em assembly x86/x64/ARM a partir de um endereço ou função.",
        "full": "Realiza desmontagem rápida via motor Capstone Disassembler, retornando os mnemônicos e operandos assembly a partir do endereço de memória ou nome da função especificado.",
        "params": {
            "procedure_or_address": "Nome do procedimento ou endereço hexadecimal (ex: 'main', '0x140001000').",
            "offset": "Deslocamento inicial de instruções a partir do início da função (padrão: 0).",
            "limit": "Quantidade de instruções assembly a desmontar (padrão: 50).",
        },
    },
    "get_call_graph": {
        "short": "Gera grafo de chamadas (caller/callee) para uma função do executável.",
        "full": "Analisa o fluxo de controle do binário e constrói o grafo de referências com as funções chamadas (callees) e funções que a chamam (callers).",
        "params": {
            "procedure_or_address": "Nome do procedimento ou endereço de memória alvo.",
            "depth": "Profundidade máxima de exploração da árvore de chamadas (padrão: 1).",
        },
    },
    "procedure_pseudo_code": {
        "short": "Gera pseudocódigo em estilo C descompilado para uma função.",
        "full": "Reconstrói a lógica de controle da função e gera pseudocódigo de alto nível em linguagem C a partir do fluxo de instruções assembly desmontado.",
        "params": {
            "procedure_or_address": "Nome ou endereço da função para gerar o pseudocódigo.",
        },
    },
    "find_xrefs_to_name": {
        "short": "Localiza referências cruzadas (XREFs) para um nome, API ou string.",
        "full": "Identifica todas as instruções e locais de código no binário que fazem referência direta ou indireta a uma função, API importada ou string específica.",
        "params": {
            "target_name": "Nome da função, API ou string para pesquisar referências cruzadas.",
            "max_results": "Limite máximo de referências cruzadas a retornar (padrão: 50).",
        },
    },
    "detect_framework": {
        "short": "Detecta frameworks e tecnologias usadas na aplicação (Electron, .NET, etc.).",
        "full": "Analisa a estrutura de pastas e assinaturas de binários para identificar se o aplicativo foi construído com Electron, .NET Core/Framework, Go, Rust, Flutter, PyInstaller ou C++ nativo.",
        "params": {
            "target_path": "Caminho do arquivo ou diretório a ser inspecionado.",
        },
    },
    "inspect_electron_asar": {
        "short": "Inspeciona e extrai arquivos compactados em pacotes Electron ASAR.",
        "full": "Lê a tabela de cabeçalho do arquivo .asar de aplicações desktop Electron, listando os arquivos JavaScript/HTML internos e permitindo extração rápida para auditoria de código.",
        "params": {
            "asar_path": "Caminho do arquivo .asar do aplicativo Electron.",
            "output_dir": "Diretório de destino opcional para extrair o conteúdo do pacote.",
            "filter_pattern": "Padrão opcional de filtro de arquivos a inspecionar/extrair.",
        },
    },
    "inspect_dotnet": {
        "short": "Inspeciona assemblies .NET compilados, metadados e dependências.",
        "full": "Analisa executáveis e DLLs .NET (CLR), identificando versão do runtime, namespaces, classes principais, métodos e ferramentas de desobfuscação recomendadas.",
        "params": {
            "file_path": "Caminho opcional do executável (.exe) ou biblioteca (.dll) .NET.",
        },
    },
    "rea_doctor": {
        "short": "Verifica integridade do ambiente REA, ferramentas instaladas e dependências.",
        "full": "Executa diagnóstico do ecossistema de engenharia reversa local: testa disponibilidade do Capstone, pefile, pyelftools, Ghidra bridge e dependências de sistema.",
        "params": {},
    },
    "list_skills": {
        "short": "Lista o catálogo completo de habilidades ativas e ferramentas do servidor MCP.",
        "full": "Exibe o catálogo completo das 8 habilidades ativas de cibersegurança e suas respectivas ferramentas integradas neste servidor MCP.",
        "params": {},
    },
}


async def index_endpoint(request: Request):
    """Serve the single page application HTML."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return PlainTextResponse("Static index.html not found.", status_code=404)


async def info_endpoint(request: Request):
    """Return platform metadata and server health."""
    tools = await server.list_tools()
    timeline = _get_timeline(limit=1)
    stealth_cfg = load_stealth_config()
    return JSONResponse({
        "platform": "Unified Cybersecurity MCP Hub",
        "version": "3.0.0",
        "status": "online",
        "total_tools": len(tools),
        "total_skills": len(SKILL_CATALOG) - 1,  # minus general
        "memory_status": "active",
        "database_file": str(unified_memory.db_path),
        "last_activity": timeline[0]["timestamp"] if timeline else None,
        "stealth_mode": stealth_cfg.get("enabled", False),
        "stealth_config": stealth_cfg,
    })


async def skills_endpoint(request: Request):
    """Return list of active cybersecurity skills with metadata."""
    tools = await server.list_tools()
    # Count tools per skill
    counts: dict[str, int] = {}
    for t in tools:
        skill = TOOL_SKILL_MAP.get(t.name, "general")
        counts[skill] = counts.get(skill, 0) + 1

    skills_list = []
    for skill_id, skill_meta in SKILL_CATALOG.items():
        skills_list.append({
            **skill_meta,
            "tool_count": counts.get(skill_id, 0),
        })

    return JSONResponse({
        "skills": skills_list,
        "total_tools": len(tools),
    })


async def tools_endpoint(request: Request):
    """Return full catalog of tools with their JSON Schema parameters."""
    tools = await server.list_tools()
    tool_list = []

    for t in tools:
        skill_id = TOOL_SKILL_MAP.get(t.name, "general")
        skill_info = SKILL_CATALOG.get(skill_id, SKILL_CATALOG["general"])
        desc_info = TOOL_DESCRIPTIONS_PT.get(t.name, {})

        full_desc = desc_info.get("full", t.description or "Sem descrição fornecida.")
        short_desc = desc_info.get("short", full_desc)
        param_descs = desc_info.get("params", {})

        tool_list.append({
            "name": t.name,
            "description": full_desc,
            "short_description": short_desc,
            "param_descriptions": param_descs,
            "input_schema": t.input_schema,
            "skill": skill_id,
            "skill_name": skill_info["name"],
            "skill_icon": skill_info["icon"],
            "skill_color": skill_info["color"],
            "example_payload": TOOL_EXAMPLES.get(t.name, {}),
        })

    # Sort tools: OSINT and Memory first, then alphabetical by skill
    tool_list.sort(key=lambda x: (x["skill"], x["name"]))

    return JSONResponse({
        "total": len(tool_list),
        "tools": tool_list,
    })

    return JSONResponse({
        "total": len(tool_list),
        "tools": tool_list,
    })


async def execute_tool_endpoint(request: Request):
    """Execute any registered MCP tool and return the output with execution metrics."""
    tool_name = request.path_params.get("tool_name", "")

    try:
        body = await request.json()
    except Exception:
        body = {}

    arguments = body.get("arguments", {})
    if not isinstance(arguments, dict):
        arguments = {}

    start_time = time.perf_counter()
    try:
        call_res = await server.call_tool(tool_name, arguments)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        raw_text = ""
        parsed_data = None

        if call_res.content:
            raw_text = call_res.content[0].text
            try:
                parsed_data = json.loads(raw_text)
            except Exception:
                parsed_data = raw_text

        is_err = getattr(call_res, "is_error", False)
        if isinstance(parsed_data, dict) and "error" in parsed_data:
            is_err = True

        return JSONResponse({
            "tool": tool_name,
            "success": not is_err,
            "is_error": is_err,
            "duration_ms": duration_ms,
            "data": parsed_data,
            "raw_text": raw_text,
        })
    except Exception as e:
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return JSONResponse({
            "tool": tool_name,
            "success": False,
            "is_error": True,
            "error": str(e),
            "duration_ms": duration_ms,
            "data": {"error": str(e)},
        }, status_code=500)


async def memory_timeline_endpoint(request: Request):
    """Retrieve chronological audit timeline from persistent memory."""
    skill = request.query_params.get("skill") or None
    limit = int(request.query_params.get("limit", "50"))
    timeline = _get_timeline(skill=skill, limit=limit)
    return JSONResponse({"timeline": timeline})


async def memory_recall_endpoint(request: Request):
    """Search and recall findings from persistent memory."""
    query = request.query_params.get("query") or None
    skill = request.query_params.get("skill") or None
    category = request.query_params.get("category") or None
    tag = request.query_params.get("tag") or None
    limit = int(request.query_params.get("limit", "20"))
    findings = _recall(query=query, skill=skill, tag=tag, category=category, limit=limit)
    return JSONResponse({"findings": findings})


async def memory_remember_endpoint(request: Request):
    """Store finding into persistent memory."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    title = body.get("title", "")
    content = body.get("content", "")
    category = body.get("category", "finding")
    tags = body.get("tags")
    skill = body.get("skill", "general")
    target_ref = body.get("target_ref")

    res = _remember(
        title=title,
        content=content,
        category=category,
        tags=tags,
        skill=skill,
        target_ref=target_ref,
    )
    return JSONResponse(res)


async def memory_report_endpoint(request: Request):
    """Export formatted Markdown dossier."""
    skill = request.query_params.get("skill") or None
    report_md = _export_investigation_report(skill=skill)
    return PlainTextResponse(report_md, media_type="text/markdown")


async def memory_clear_endpoint(request: Request):
    """Clear memory."""
    res = _clear_memory(confirm=True)
    return JSONResponse(res)


async def stealth_status_endpoint(request: Request):
    """Return current stealth mode configuration and active status."""
    cfg = load_stealth_config()
    return JSONResponse(cfg)


async def stealth_configure_endpoint(request: Request):
    """Configure and toggle stealth mode."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    enabled = body.get("enabled", True)
    proxy_url = body.get("proxy_url", "socks5://127.0.0.1:9050")
    dns_over_tor = body.get("dns_over_tor", True)
    res = _configure_stealth_mode(enabled=enabled, proxy_url=proxy_url, dns_over_tor=dns_over_tor)
    return JSONResponse(res)


async def stealth_test_endpoint(request: Request):
    """Test connectivity to the Tor Onion node."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    proxy_url = body.get("proxy_url")
    timeout = float(body.get("timeout", 6.0))
    res = _test_tor_connection(proxy_url=proxy_url, timeout=timeout)
    return JSONResponse(res)


routes = [
    Route("/", endpoint=index_endpoint, methods=["GET"]),
    Route("/api/info", endpoint=info_endpoint, methods=["GET"]),
    Route("/api/skills", endpoint=skills_endpoint, methods=["GET"]),
    Route("/api/tools", endpoint=tools_endpoint, methods=["GET"]),
    Route("/api/tools/{tool_name}/execute", endpoint=execute_tool_endpoint, methods=["POST"]),
    Route("/api/stealth/status", endpoint=stealth_status_endpoint, methods=["GET"]),
    Route("/api/stealth/configure", endpoint=stealth_configure_endpoint, methods=["POST"]),
    Route("/api/stealth/test", endpoint=stealth_test_endpoint, methods=["POST"]),
    Route("/api/memory/timeline", endpoint=memory_timeline_endpoint, methods=["GET"]),
    Route("/api/memory/recall", endpoint=memory_recall_endpoint, methods=["GET"]),
    Route("/api/memory/remember", endpoint=memory_remember_endpoint, methods=["POST"]),
    Route("/api/memory/report", endpoint=memory_report_endpoint, methods=["GET"]),
    Route("/api/memory/clear", endpoint=memory_clear_endpoint, methods=["POST"]),
    Mount("/static", app=StaticFiles(directory=str(STATIC_DIR)), name="static"),
]

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    ),
]

app = Starlette(debug=True, routes=routes, middleware=middleware)
