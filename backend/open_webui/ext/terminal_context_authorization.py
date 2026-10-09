"""Authorization for terminal chat-scoped runtime contexts."""

from open_webui.env import ENABLE_ADMIN_CHAT_ACCESS
from open_webui.models.chats import Chats, is_internal_chat
from open_webui.utils.chat_id import is_saved_chat_id


async def authorized_terminal_chat_context(user, chat_id: str) -> str | None:
    """Return a saved chat ID only for its owner or authorized administrator."""
    if not isinstance(chat_id, str) or not is_saved_chat_id(chat_id):
        return None
    chat = await Chats.get_chat_by_id(chat_id)
    if chat is None:
        return None
    if chat.user_id == user.id:
        return chat_id
    if user.role == 'admin' and (ENABLE_ADMIN_CHAT_ACCESS or is_internal_chat(chat.meta)):
        return chat_id
    return None


async def resolve_terminal_chat_context(user, chat_id: str) -> tuple[str | None, bool]:
    """Return a safe chat ID and whether it is an authorized saved chat.

    Temporary, local, and channel IDs are safe for session tracking but never
    select a chat-scoped terminal runtime. Saved IDs fail closed unless the
    caller is authorized to use that chat as a terminal context.
    """
    if not isinstance(chat_id, str) or not chat_id:
        return '', False
    if not is_saved_chat_id(chat_id):
        return chat_id, False

    authorized_chat_id = await authorized_terminal_chat_context(user, chat_id)
    return authorized_chat_id, bool(authorized_chat_id)
