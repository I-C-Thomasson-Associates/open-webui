"""Terminal authorization (find_machine_connection) and AGENTS.md read tests.

find_machine_connection is the real production function; only its storage and
access collaborators are replaced, so the fork's chat-owner rule (item 25) and
the duplicate-ID rule run as shipped.
"""

import ast
import asyncio
import logging
import ntpath
import posixpath
from pathlib import Path
from urllib.parse import quote
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from open_webui.ext import terminal_context_authorization as chat_authorization
from open_webui.models import chats as chats_module, users as users_module
from open_webui.models.users import UserModel
from open_webui.utils import access_control, machines, tether

SRC = Path(__file__).parents[1] / 'utils' / 'machines' / '__init__.py'


def _user(id='u1', role='user'):
    return UserModel(id=id, email=f'{id}@example.test', name=id, role=role, last_active_at=0, updated_at=0, created_at=0)


def _conn(**kw):
    return {'id': 't', 'url': 'http://t', **kw}


def _chat(user_id, **meta):
    return SimpleNamespace(id='chat-1', user_id=user_id, meta=meta, chat={}, folder_id=None, current_message_id='m1')


@pytest.fixture
def world(monkeypatch):
    """Patch collaborators of the real find_machine_connection; returns the fakes."""
    from open_webui.utils.agents import session

    chats = SimpleNamespace(
        get_accessible_chat_by_id=AsyncMock(), get_chat_by_id=AsyncMock(), get_chat_metadata_by_id=AsyncMock()
    )

    async def has_chat_access(chat_id, user, **_):
        # Upstream 0.13.5 checks access on metadata; reuse the per-user accessible-chat fake.
        return await chats.get_accessible_chat_by_id(chat_id, user) is not None

    chats.has_chat_access = has_chat_access
    w = SimpleNamespace(
        chats=chats,
        users=SimpleNamespace(get_user_by_id=AsyncMock()),
        connections=AsyncMock(return_value=[_conn()]),
        access=AsyncMock(return_value=True),
        write=AsyncMock(return_value=False),
    )
    monkeypatch.setattr(machines, 'ENABLE_TOOL_SERVERS', True)
    monkeypatch.setattr(machines, 'has_machine_write_access', w.write)
    monkeypatch.setattr(chats_module, 'Chats', chats)
    monkeypatch.setattr(chat_authorization, 'Chats', chats)
    monkeypatch.setattr(chat_authorization, 'ENABLE_ADMIN_CHAT_ACCESS', False)
    monkeypatch.setattr(users_module, 'Users', w.users)
    monkeypatch.setattr(access_control, 'has_connection_access', w.access)
    monkeypatch.setattr(tether, 'get_machine_connections', w.connections)
    monkeypatch.setattr(session, 'get_session', AsyncMock(return_value=None))
    return w


async def _find(user, chat_id=None):
    return await machines.find_machine_connection(user, 't', {'chat_id': chat_id} if chat_id else {})


@pytest.mark.asyncio
async def test_duplicate_ids_are_ambiguous_before_access_check(world):
    world.connections.return_value = [_conn(), _conn(url='http://other')]
    with pytest.raises(HTTPException) as exc:
        await _find(_user())
    assert (exc.value.status_code, exc.value.detail) == (409, 'Ambiguous machine ID')
    world.access.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('case', ['disabled', 'no-access', 'missing'])
async def test_disabled_inaccessible_or_missing_terminal_is_not_found(world, case):
    if case == 'disabled':
        world.connections.return_value = [_conn(enabled=False)]
    elif case == 'no-access':
        world.access.return_value = False
    else:
        world.connections.return_value = []
    assert await _find(_user()) is None


@pytest.mark.asyncio
async def test_single_accessible_connection_resolves_without_chat(world):
    assert await _find(_user()) == _conn()
    world.chats.get_accessible_chat_by_id.assert_not_awaited()


@pytest.mark.asyncio
async def test_saved_chat_owner_uses_terminal_without_admin_lookup(world):
    world.chats.get_accessible_chat_by_id.return_value = _chat('u1')
    world.chats.get_chat_metadata_by_id.return_value = _chat('u1')
    assert await _find(_user('u1'), 'chat-1') == _conn()
    world.chats.get_chat_by_id.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('role', ['user', 'admin'])
@pytest.mark.parametrize('meta', [{}, {'shared': True}, {'folder_id': 'writable-folder'}])
async def test_foreign_accessible_chat_never_selects_owner_terminal(world, role, meta):
    # Fork item 25: reply/folder-write access to someone else's chat is not terminal access.
    world.chats.get_accessible_chat_by_id.return_value = _chat('owner', **meta)
    world.chats.get_chat_by_id.return_value = _chat('owner', **meta)
    world.chats.get_chat_metadata_by_id.return_value = _chat('owner', **meta)
    with pytest.raises(HTTPException) as exc:
        await _find(_user('u1', role), 'chat-1')
    assert (exc.value.status_code, exc.value.detail) == (403, 'Chat access denied')
    world.connections.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('admin_chat_access, meta', [(True, {}), (False, {'internal': True})])
async def test_admin_may_use_foreign_chat_only_with_configured_access(world, monkeypatch, admin_chat_access, meta):
    # Upstream 0.13.5 (#35031): internal chats no longer bypass ENABLE_ADMIN_CHAT_ACCESS.
    monkeypatch.setattr(chat_authorization, 'ENABLE_ADMIN_CHAT_ACCESS', admin_chat_access)
    world.chats.get_accessible_chat_by_id.return_value = _chat('owner', **meta)
    world.chats.get_chat_metadata_by_id.return_value = _chat('owner', **meta)
    if admin_chat_access:
        assert await _find(_user('admin', 'admin'), 'chat-1') == _conn()
    else:
        with pytest.raises(HTTPException) as exc:
            await _find(_user('admin', 'admin'), 'chat-1')
        assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_foreign_chat_with_terminal_write_access_reaches_owner_instance(world):
    owner = _user('owner')
    world.write.return_value = True
    world.users.get_user_by_id.return_value = owner
    world.chats.get_chat_by_id.return_value = _chat('owner')
    world.chats.get_chat_metadata_by_id.return_value = _chat('owner')
    # The manager's reply access is foreign (denied above); write access routes them to the owner's instance.
    world.chats.get_accessible_chat_by_id.side_effect = lambda chat_id, user, **_: _chat('owner') if user.id == 'owner' else _chat('owner', shared=True)

    connection = await _find(_user('manager'), 'chat-1')

    assert connection['instance_user_id'] == 'owner'
    assert world.connections.await_args.args[0].id == 'owner'


@pytest.mark.asyncio
async def test_deleted_chat_is_denied(world):
    world.chats.get_accessible_chat_by_id.return_value = None
    world.chats.get_chat_by_id.return_value = None
    world.chats.get_chat_metadata_by_id.return_value = None
    with pytest.raises(HTTPException) as exc:
        await _find(_user(), 'chat-1')
    assert (exc.value.status_code, exc.value.detail) == (403, 'Chat access denied')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'content,expected',
    [('instructions', '# AGENTS.md\n\ninstructions'), ('x' * 32769, None)],
    ids=['small', 'oversized'],  # Windows caps PYTEST_CURRENT_TEST at 32767 chars
)
async def test_agents_read_requests_runtime_byte_bound_and_checks_response(content, expected):
    tree = ast.parse(SRC.read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'get_machine_agents_md')
    fetch = AsyncMock(side_effect=[{'home': '/home/user'}, {'content': content}])
    scope = {
        'asyncio': asyncio, 'ntpath': ntpath, 'posixpath': posixpath, 'quote': quote,
        'get_machine_json': fetch, 'MAX_AGENTS_MD_BYTES': 32768,
        'get_chat_folder_directory': AsyncMock(return_value=None),
        'log': logging.getLogger(__name__),
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SRC), 'exec'), scope)
    metadata, extra = {'machine_id': 't', 'chat_id': 'saved'}, {'__event_call__': object()}
    assert await scope['get_machine_agents_md'](None, _user(), metadata, extra) == expected
    assert fetch.await_args.args[3] == '/files/read?path=%2Fhome%2Fuser%2FAGENTS.md&max_bytes=32768'
    assert fetch.await_args.args[2] is metadata
    assert fetch.await_args.args[4] is extra
