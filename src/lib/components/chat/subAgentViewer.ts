import { get, writable, type Readable } from 'svelte/store';

export type SubAgentChat = { chatId: string; title: string };

const emptyScope = (parentId = '', userId = '', scopeRevision = 0) => ({
	parentId,
	userId,
	scopeRevision,
	catalog: [] as SubAgentChat[],
	selectedId: '',
	openRevision: 0
});
export const subAgentViewer = writable(emptyScope());
let scopeOwner: symbol | null = null;

// Only the mounted chat controls owns scope; response teardown must not clear sibling catalogs.
export function trackSubAgentScope(
	activeChat: Readable<string>,
	activeUser: Readable<{ id: string } | null | undefined>
) {
	const owner = Symbol();
	scopeOwner = owner;
	const sync = () => {
		if (scopeOwner !== owner) return;
		const parentId = get(activeChat) ?? '';
		const userId = get(activeUser)?.id ?? '';
		subAgentViewer.update((state) =>
			state.parentId === parentId && state.userId === userId
				? state
				: emptyScope(parentId, userId, state.scopeRevision + 1)
		);
	};
	const offChat = activeChat.subscribe(sync);
	const offUser = activeUser.subscribe(sync);
	return () => {
		offChat();
		offUser();
		if (scopeOwner === owner) {
			scopeOwner = null;
			subAgentViewer.update((state) => emptyScope('', '', state.scopeRevision + 1));
		}
	};
}

export function createSubAgentBridge(
	parentId: string,
	userId: string,
	readOnly: boolean,
	scopeRevision: number
) {
	return (value: unknown, source: Window): boolean => {
		const state = get(subAgentViewer);
		if (
			readOnly ||
			!scopeOwner ||
			!parentId ||
			!userId ||
			state.parentId !== parentId ||
			state.userId !== userId ||
			state.scopeRevision !== scopeRevision ||
			!value ||
			typeof value !== 'object'
		)
			return false;
		const data = value as Record<string, unknown>;
		let chats: SubAgentChat[];
		if (data.type === 'subagent:chats' && Array.isArray(data.chats) && data.chats.length <= 64) {
			const parsed = data.chats.map(parseSubAgentChat);
			if (parsed.some((chat) => !chat)) return false;
			chats = parsed as SubAgentChat[];
		} else if (data.type === 'subagent:open-chat') {
			const chat = parseSubAgentChat(data);
			if (!chat) return false;
			chats = [chat];
		} else return false;
		const catalog = mergeSubAgentChats(state.catalog, chats);
		if (data.type === 'subagent:open-chat' && !catalog.some((chat) => chat.chatId === data.chatId))
			return false;
		subAgentViewer.set({
			...state,
			catalog,
			selectedId:
				data.type === 'subagent:open-chat'
					? chats[0].chatId
					: state.selectedId || catalog[0]?.chatId || '',
			openRevision: state.openRevision + (data.type === 'subagent:open-chat' ? 1 : 0)
		});
		// Ack only validated catalogs, and only to the iframe that sent them.
		if (data.type === 'subagent:chats') source.postMessage({ type: 'subagent:viewer-ready' }, '*');
		return true;
	};
}

export function selectSubAgentChat(id: string) {
	subAgentViewer.update((state) =>
		state.catalog.some((chat) => chat.chatId === id) ? { ...state, selectedId: id } : state
	);
}

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
