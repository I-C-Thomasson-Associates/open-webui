export type SubAgentChat = { chatId: string; title: string };

export function parseSubAgentChat(value: unknown): SubAgentChat | null {
	if (!value || typeof value !== 'object') return null;
	const { chatId, title } = value as Record<string, unknown>;
	if (
		typeof chatId !== 'string' ||
		!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(chatId) ||
		typeof title !== 'string' ||
		title.length > 200
	)
		return null;
	return { chatId, title: title.trim() || 'Sub-agent' };
}

export function isOwnedSubAgentChat(
	chat: any,
	id: string,
	userId: string,
	parentId: string
): boolean {
	return (
		!!userId &&
		!!parentId &&
		chat?.id === id &&
		chat?.user_id === userId &&
		chat?.meta?.internal === true &&
		chat.meta.type === 'subagent' &&
		chat.meta.source === 'ai_team_delegate' &&
		chat.meta.parent_chat_id === parentId
	);
}

export function mergeSubAgentChats(
	existing: SubAgentChat[],
	incoming: SubAgentChat[]
): SubAgentChat[] {
	const chats = new Map(existing.map((chat) => [chat.chatId, chat]));
	for (const chat of incoming)
		if (chats.has(chat.chatId) || chats.size < 64) chats.set(chat.chatId, chat);
	return [...chats.values()];
}
