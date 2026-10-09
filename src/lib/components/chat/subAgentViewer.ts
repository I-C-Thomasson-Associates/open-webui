import { get, writable, type Readable } from 'svelte/store';
import { getSubAgentChats } from '$lib/ext/subagent-chats-api';
import { socket } from '$lib/stores';

export type SubAgentChat = { chatId: string; title: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const emptyScope = (parentId = '', userId = '', scopeRevision = 0) => ({
	parentId,
	userId,
	scopeRevision,
	catalog: [] as SubAgentChat[],
	discovery: 'idle' as 'idle' | 'loading' | 'ready' | 'error',
	selectedId: '',
	openRevision: 0
});
export const subAgentViewer = writable(emptyScope());
let scopeOwner: symbol | null = null;
let stopScope: (() => void) | null = null;
let catalogRequest: AbortController | null = null;
let refreshQueued = false;
// Live registrations seen while the current API request is in flight; they win over that response.
let catalogLive: Map<string, SubAgentChat> | null = null;
const abortCatalog = () => {
	catalogRequest?.abort();
	catalogRequest = null;
	catalogLive = null;
	refreshQueued = false;
};
const recordLive = (chats: SubAgentChat[]) => {
	for (const chat of chats) catalogLive?.set(chat.chatId, chat);
};

// queue (live reconnect/replace paths) remembers one refresh requested while another is in flight.
export async function refreshSubAgentCatalog(queue = false) {
	const scope = get(subAgentViewer);
	const owner = scopeOwner;
	if (
		typeof window === 'undefined' ||
		!owner ||
		!scope.userId ||
		!uuid.test(scope.parentId)
	)
		return;
	if (catalogRequest) {
		if (queue) refreshQueued = true;
		return;
	}
	const request = new AbortController();
	const live = new Map<string, SubAgentChat>();
	catalogRequest = request;
	catalogLive = live;
	const current = () => {
		const state = get(subAgentViewer);
		return (
			!request.signal.aborted &&
			catalogRequest === request &&
			scopeOwner === owner &&
			state.scopeRevision === scope.scopeRevision &&
			state.parentId === scope.parentId &&
			state.userId === scope.userId
		);
	};
	// A refresh over an already-ready catalog is background reconciliation: no spinner, no error flash.
	const quiet = scope.discovery === 'ready';
	if (!quiet) subAgentViewer.update((state) => ({ ...state, discovery: 'loading' }));
	try {
		const result = await getSubAgentChats(localStorage.token, scope.parentId, request.signal);
		if (!current()) return;
		if (!Array.isArray(result)) throw new Error('Unavailable');
		const parsed = result.map(parseSubAgentChat);
		if (parsed.some((chat) => !chat)) throw new Error('Unavailable');
		subAgentViewer.update((state) => {
			// The server is authoritative (deleted children drop out); only registrations seen during this request win.
			const catalog = mergeSubAgentChats(parsed as SubAgentChat[], [...live.values()]);
			return {
				...state,
				catalog,
				selectedId: catalog.some((chat) => chat.chatId === state.selectedId)
					? state.selectedId
					: catalog[0]?.chatId || '',
				discovery: 'ready'
			};
		});
	} catch {
		if (current() && !quiet) subAgentViewer.update((state) => ({ ...state, discovery: 'error' }));
	} finally {
		if (catalogRequest === request) {
			catalogRequest = null;
			catalogLive = null;
			if (refreshQueued) {
				refreshQueued = false;
				void refreshSubAgentCatalog(true);
			}
		}
	}
}

// Only the mounted chat controls owns scope; response teardown must not clear sibling catalogs.
export function trackSubAgentScope(
	activeChat: Readable<string>,
	activeUser: Readable<{ id: string } | null | undefined>,
	socketStore: Readable<any> = socket
) {
	stopScope?.();
	const owner = Symbol();
	scopeOwner = owner;
	const sync = () => {
		if (scopeOwner !== owner) return;
		const parentId = get(activeChat) ?? '';
		const userId = get(activeUser)?.id ?? '';
		const state = get(subAgentViewer);
		if (state.parentId !== parentId || state.userId !== userId) {
			abortCatalog();
			subAgentViewer.set(emptyScope(parentId, userId, state.scopeRevision + 1));
		}
		if (get(subAgentViewer).discovery === 'idle') void refreshSubAgentCatalog();
	};
	const offChat = activeChat.subscribe(sync);
	const offUser = activeUser.subscribe(sync);
	// The tool emits the spawn on the parent chat's socket stream, independent of the dashboard iframe.
	const onEvent = (event: any) => {
		const state = get(subAgentViewer);
		const payload = event?.data;
		if (
			scopeOwner !== owner ||
			!state.userId ||
			!state.parentId ||
			event?.chat_id !== state.parentId ||
			payload?.type !== 'subagent:catalog'
		)
			return;
		const body = payload.data;
		let chats: SubAgentChat[];
		if (Array.isArray(body?.chats) && body.chats.length <= 64) {
			const parsed = body.chats.map(parseSubAgentChat);
			if (!parsed.length || parsed.some((chat: unknown) => !chat)) return;
			chats = parsed;
		} else {
			const chat = parseSubAgentChat(body);
			if (!chat) return;
			chats = [chat];
		}
		recordLive(chats);
		subAgentViewer.update((current) => {
			const catalog = mergeSubAgentChats(current.catalog, chats);
			return { ...current, catalog, selectedId: current.selectedId || catalog[0]?.chatId || '' };
		});
	};
	// A reconnect or replaced socket may have missed spawns; one reconciling refresh recovers them.
	const onConnect = () => {
		if (scopeOwner === owner) void refreshSubAgentCatalog(true);
	};
	let connected: any = null;
	let first = true;
	const offSocket = socketStore.subscribe((value) => {
		connected?.off('events', onEvent);
		connected?.off('connect', onConnect);
		connected = value;
		connected?.on('events', onEvent);
		connected?.on('connect', onConnect);
		if (!first && value) onConnect();
		first = false;
	});
	const cleanup = () => {
		offChat();
		offUser();
		offSocket();
		connected?.off('events', onEvent);
		connected?.off('connect', onConnect);
		connected = null;
		if (scopeOwner === owner) {
			abortCatalog();
			scopeOwner = null;
			stopScope = null;
			subAgentViewer.update((state) => emptyScope('', '', state.scopeRevision + 1));
		}
	};
	stopScope = cleanup;
	return cleanup;
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
		recordLive(chats);
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
		!uuid.test(chatId) ||
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
	for (const chat of incoming) chats.set(chat.chatId, chat);
	return [...chats.values()];
}
