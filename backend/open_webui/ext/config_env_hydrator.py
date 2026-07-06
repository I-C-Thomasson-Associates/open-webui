from __future__ import annotations

import ast
import os
from pathlib import Path

from open_webui.secrets import get_secret_from_vault


def _extract_string_key(call: ast.Call) -> str | None:
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value

    for keyword in call.keywords:
        if keyword.arg == 'key' and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return keyword.value.value

    return None


def _is_os_getenv_call(call: ast.Call) -> bool:
    func = call.func
    return isinstance(func, ast.Attribute) and func.attr == 'getenv' and isinstance(func.value, ast.Name) and func.value.id == 'os'


def _is_os_environ_get_call(call: ast.Call) -> bool:
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == 'get'):
        return False

    value = func.value
    return (
        isinstance(value, ast.Attribute)
        and value.attr == 'environ'
        and isinstance(value.value, ast.Name)
        and value.value.id == 'os'
    )


def discover_env_keys_from_file(file_path: Path) -> set[str]:
    keys: set[str] = set()

    try:
        tree = ast.parse(file_path.read_text(encoding='utf-8'))
    except Exception:
        return keys

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not (_is_os_getenv_call(node) or _is_os_environ_get_call(node)):
            continue

        key = _extract_string_key(node)
        if key:
            keys.add(key)

    return keys


def discover_env_keys(open_webui_dir: Path, include_env: bool = True, include_config: bool = True) -> set[str]:
    keys: set[str] = set()

    if include_env:
        keys.update(discover_env_keys_from_file(open_webui_dir / 'env.py'))

    if include_config:
        keys.update(discover_env_keys_from_file(open_webui_dir / 'config.py'))

    return keys


def hydrate_env_from_vault(
    open_webui_dir: Path,
    include_env: bool = True,
    include_config: bool = True,
    overwrite: bool = True,
    include_key_details: bool = False,
) -> dict[str, int | list[str]]:
    keys = discover_env_keys(open_webui_dir=open_webui_dir, include_env=include_env, include_config=include_config)

    hydrated = 0
    missing = 0
    skipped = 0
    hydrated_keys: list[str] = []
    missing_keys: list[str] = []
    skipped_keys: list[str] = []

    for key in sorted(keys):
        value = get_secret_from_vault(key)
        if value is None:
            missing += 1
            if include_key_details:
                missing_keys.append(key)
            continue

        if overwrite or key not in os.environ:
            os.environ[key] = value
            hydrated += 1
            if include_key_details:
                hydrated_keys.append(key)
        else:
            skipped += 1
            if include_key_details:
                skipped_keys.append(key)

    stats: dict[str, int | list[str]] = {
        'discovered': len(keys),
        'hydrated': hydrated,
        'missing': missing,
        'skipped': skipped,
    }

    if include_key_details:
        stats['hydrated_keys'] = hydrated_keys
        stats['missing_keys'] = missing_keys
        stats['skipped_keys'] = skipped_keys

    return stats
