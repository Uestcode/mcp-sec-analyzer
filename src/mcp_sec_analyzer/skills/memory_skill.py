"""Universal memory tools exposed via MCP."""

from __future__ import annotations

from typing import Any

from ..core.decorator import skill_tool
from ..core.memory import unified_memory


@skill_tool(skill="memory")
def remember(
    title: str,
    content: str,
    category: str = "finding",
    tags: list[str] | str | None = None,
    skill: str = "general",
    target_ref: str | None = None,
) -> dict[str, Any]:
    """Save an observation, insight, hypothesis, IOC, or note into persistent memory.

    Persists across sessions in local SQLite database so you never lose context.

    Args:
        title: Short descriptive title of the finding or note.
        content: Detailed explanation, code snippet, or observation.
        category: Category type: 'finding', 'note', 'hypothesis', 'ioc', 'architecture', 'todo'.
        tags: Optional list of tags or comma-separated string (e.g., ['crypto', 'xor', 'auth']).
        skill: Relevant skill domain (e.g., 'rea', 'code_audit', 'general').
        target_ref: Optional target reference (e.g., function name, address '0x140001000', file path).
    """
    return unified_memory.remember(
        title=title,
        content=content,
        category=category,
        tags=tags,
        skill=skill,
        target_ref=target_ref,
    )


@skill_tool(skill="memory")
def recall(
    query: str | None = None,
    skill: str | None = None,
    tag: str | None = None,
    category: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Search and recall past findings, notes, and context from persistent memory.

    Args:
        query: Substring search across titles and content.
        skill: Filter by specific skill (e.g., 'rea', 'code_audit').
        tag: Filter by tag (e.g., 'crypto').
        category: Filter by category ('finding', 'note', 'hypothesis', 'ioc', 'todo').
        limit: Maximum items to return (default: 20).
    """
    return unified_memory.recall(
        query=query,
        skill=skill,
        tag=tag,
        category=category,
        limit=limit,
    )


@skill_tool(skill="memory")
def get_timeline(
    skill: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Retrieve chronological history of actions executed across any or all skills.

    Args:
        skill: Optional filter to view actions only from a specific skill (e.g., 'rea').
        limit: Maximum timeline entries to return (default: 50).
    """
    return unified_memory.get_timeline(
        skill=skill,
        limit=limit,
    )


@skill_tool(skill="memory")
def export_investigation_report(
    skill: str | None = None,
) -> str:
    """Generate and export a comprehensive Markdown investigation dossier and report.

    Consolidates session target details, all saved knowledge findings, and the execution timeline.

    Args:
        skill: Optional filter to report only on a specific skill.
    """
    return unified_memory.export_report(skill=skill)


@skill_tool(skill="memory")
def clear_memory(
    confirm: bool = False,
    skill: str | None = None,
) -> dict[str, str]:
    """Purge memory records for a specific skill or entire database.

    Args:
        confirm: Must be explicitly set to True to prevent accidental deletion.
        skill: Optional skill name to purge only that skill's records.
    """
    return unified_memory.clear(confirm=confirm, skill=skill)
