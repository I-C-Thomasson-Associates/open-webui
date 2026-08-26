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
