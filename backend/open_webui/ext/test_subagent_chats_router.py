from types import SimpleNamespace
from contextlib import asynccontextmanager
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from open_webui.ext import subagent_chats_router as router_module
from open_webui.models.chats import Chat
from open_webui.utils.auth import get_verified_user

OWNER = SimpleNamespace(id='owner', role='user')
PARENT = str(uuid4())
META = {'internal': True, 'type': 'subagent', 'source': 'ai_team_delegate', 'parent_chat_id': PARENT}


def _chat(chat_id=None, user_id='owner', title='Child', created_at=1, meta=None, **extra):
    return Chat(
        id=chat_id or str(uuid4()),
        user_id=user_id,
        title=title,
        chat={'history': {'messages': {'m': {'content': 'SECRET transcript'}}}},
        created_at=created_at,
        updated_at=created_at,
        meta={**META, **(meta or {})},
        **extra,
    )


@pytest_asyncio.fixture
async def session_factory(monkeypatch):
    engine = create_async_engine('sqlite+aiosqlite://')
    async with engine.begin() as conn:
        await conn.run_sync(Chat.__table__.create)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def context():
        async with factory() as session:
            yield session

    monkeypatch.setattr(router_module, 'get_async_db_context', context)
    yield factory
    await engine.dispose()


async def _seed(factory, *chats):
    async with factory() as session:
        session.add_all(chats)
        await session.commit()


async def _call(parent_id=PARENT, user=OWNER):
    return await router_module.get_subagent_chats(parent_id, user=user)


def test_route_is_mounted_get_with_verified_user_dependency():
    app = FastAPI()
    app.include_router(router_module.router, prefix='/api/v1/ext/subagent-chats')
    route = next(r for r in app.routes if r.path == '/api/v1/ext/subagent-chats/{parent_id}')
    assert route.methods == {'GET'}
    assert [d.call for d in route.dependant.dependencies] == [get_verified_user]


@pytest.mark.asyncio
async def test_returns_only_owned_matching_children_oldest_first(session_factory):
    a, b, c = sorted(str(uuid4()) for _ in range(3))
    await _seed(
        session_factory,
        _chat(PARENT, title='Parent', meta={'internal': False}),
        _chat(c, created_at=5, title='late'),
        _chat(b, created_at=1, title='tie-b'),
        _chat(a, created_at=1, title='tie-a'),
        _chat(user_id='other', title='other user'),
        _chat(meta={'internal': False}),
        _chat(meta={'type': 'note'}),
        _chat(meta={'source': 'native'}),
        _chat(meta={'parent_chat_id': str(uuid4())}),
        _chat('not-a-uuid'),
    )

    result = await _call()

    assert result == [
        {'chatId': a, 'title': 'tie-a'},
        {'chatId': b, 'title': 'tie-b'},
        {'chatId': c, 'title': 'late'},
    ]
    assert 'SECRET' not in repr(result)


@pytest.mark.asyncio
async def test_missing_foreign_malformed_and_shared_parent_all_404(session_factory):
    foreign = str(uuid4())
    await _seed(session_factory, _chat(foreign, user_id='other', meta={'internal': False}))
    for parent_id in (str(uuid4()), foreign, 'not-a-uuid', PARENT.upper()):
        with pytest.raises(HTTPException) as exc:
            await _call(parent_id)
        assert (exc.value.status_code, exc.value.detail) == (404, 'Not found')
    # Admins get no exception.
    with pytest.raises(HTTPException):
        await _call(foreign, SimpleNamespace(id='admin', role='admin'))


@pytest.mark.asyncio
async def test_empty_owned_parent_and_over_64_children(session_factory):
    await _seed(session_factory, _chat(PARENT, meta={'internal': False}))
    assert await _call() == []

    await _seed(session_factory, *[_chat(created_at=i) for i in range(70)])
    assert len(await _call()) == 70


@pytest.mark.asyncio
async def test_title_is_bounded_and_defaulted(session_factory):
    await _seed(
        session_factory,
        _chat(PARENT, meta={'internal': False}),
        _chat(title='x' * 500, created_at=1),
        _chat(title='   ', created_at=2),
        _chat(title=None, created_at=3),
    )
    assert [r['title'] for r in await _call()] == ['x' * 200, 'New Chat', 'New Chat']


@pytest.mark.asyncio
async def test_title_cap_is_utf16_units_without_splitting_emoji(session_factory):
    emoji = '\U0001F600'
    cases = [emoji * 101, 'a' + emoji * 100, 'ab' + emoji * 99, 'é' * 201, emoji * 3]
    await _seed(
        session_factory,
        _chat(PARENT, meta={'internal': False}),
        *[_chat(title=t, created_at=i) for i, t in enumerate(cases, 1)],
    )
    result = await _call()
    assert [r['title'] for r in result] == [emoji * 100, 'a' + emoji * 99, 'ab' + emoji * 99, 'é' * 200, emoji * 3]
    assert len(result) == len(cases)
    assert all(len(r['title'].encode('utf-16-le')) // 2 <= 200 for r in result)


@pytest.mark.asyncio
async def test_internal_must_be_json_boolean_true(session_factory):
    wrong = [1, 0, 'true', 'yes', 'note', '1', None, [], [True], {}, {'a': True}, False]
    good = str(uuid4())
    absent = _chat(created_at=1, title='absent')
    absent.meta = {k: v for k, v in META.items() if k != 'internal'}
    await _seed(
        session_factory,
        _chat(PARENT, meta={'internal': False}),
        *[_chat(meta={'internal': v}, created_at=1, title=f'wrong {v!r}') for v in wrong],
        absent,
        _chat(good, created_at=2, title='good'),
    )
    assert await _call() == [{'chatId': good, 'title': 'good'}]


def test_sql_selects_only_id_title_and_never_casts_internal_to_boolean():
    from sqlalchemy import select

    for dialect in (sqlite.dialect(), postgresql.dialect()):
        stmt = select(Chat.id, Chat.title).where(
            router_module._internal_is_json_true(dialect.name),
            Chat.meta['parent_chat_id'].as_string() == PARENT,
        )
        sql = str(stmt.compile(dialect=dialect))
        assert sql.startswith('SELECT chat.id, chat.title')
        assert 'chat.chat' not in sql
        assert 'AS BOOLEAN' not in sql.upper()

    sqlite_sql = str(
        select(Chat.id).where(router_module._internal_is_json_true('sqlite')).compile(dialect=sqlite.dialect())
    )
    assert 'json_type(chat.meta, ?) = ?' in sqlite_sql
    pg_sql = str(
        select(Chat.id).where(router_module._internal_is_json_true('postgresql')).compile(dialect=postgresql.dialect())
    )
    assert 'json_typeof((chat.meta -> %(meta_1)s)) = %(json_typeof_1)s' in pg_sql
    assert 'CAST((chat.meta ->> %(meta_2)s) AS VARCHAR) = %(param_1)s' in pg_sql


def test_unsupported_dialect_raises():
    with pytest.raises(NotImplementedError):
        router_module._internal_is_json_true('mysql')