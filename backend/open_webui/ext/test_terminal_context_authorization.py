from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from open_webui.ext import terminal_context_authorization as authorization


@pytest.mark.asyncio
async def test_authorized_terminal_context_accepts_owner(monkeypatch):
    get_chat = AsyncMock(return_value=SimpleNamespace(id='chat-id', user_id='user-id', meta={}))
    monkeypatch.setattr(authorization.Chats, 'get_chat_by_id', get_chat)

    assert await authorization.authorized_terminal_chat_context(SimpleNamespace(id='user-id'), 'chat-id') == 'chat-id'
    get_chat.assert_awaited_once_with('chat-id')


@pytest.mark.asyncio
async def test_authorized_terminal_context_allows_configured_admin(monkeypatch):
    monkeypatch.setattr(authorization, 'ENABLE_ADMIN_CHAT_ACCESS', True)
    monkeypatch.setattr(authorization.Chats, 'get_chat_by_id', AsyncMock(return_value=SimpleNamespace(id='chat-id', user_id='owner', meta={})))
    assert await authorization.authorized_terminal_chat_context(SimpleNamespace(id='admin', role='admin'), 'chat-id') == 'chat-id'


@pytest.mark.asyncio
async def test_authorized_terminal_context_rejects_shared_folder_foreign_missing_and_temporary(monkeypatch):
    get_chat = AsyncMock(return_value=SimpleNamespace(id='foreign-chat', user_id='owner', meta={}))
    monkeypatch.setattr(authorization.Chats, 'get_chat_by_id', get_chat)
    user = SimpleNamespace(id='user-id', role='user')

    assert await authorization.authorized_terminal_chat_context(user, 'foreign-chat') is None
    assert await authorization.authorized_terminal_chat_context(user, '') is None
    get_chat.assert_awaited_once_with('foreign-chat')
