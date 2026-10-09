import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { compile } from 'svelte/compiler';
import { describe, expect, it, vi } from 'vitest';
import { isOwnedSubAgentChat } from './subAgentViewer';

const id = '12345678-1234-1234-1234-123456789abc';
const secondId = '22345678-1234-1234-1234-123456789abc';
const saved = {
	id,
	user_id: 'owner',
	meta: { internal: true, type: 'subagent', source: 'ai_team_delegate', parent_chat_id: 'parent' },
	chat: { history: { currentId: 'assistant', messages: { assistant: { done: false } } } }
};
const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function controller(fetchChat: (...args: any[]) => any) {
	const source = readFileSync(new URL('./SubAgentChatViewer.svelte', import.meta.url), 'utf8');
	const script = source
		.match(/<script lang="ts">([\s\S]*?)<\/script>/)![1]
		.replace(/\bimport[\s\S]*?from\s+['"][^'"]+['"];?/g, '')
		.replace(/\bexport\s+/g, '')
		.replace(/^\s*\$:[\s\S]*?(?=\n\n\tasync function refresh)/m, '');
	const code = ts.transpileModule(script, {
		compilerOptions: { target: ts.ScriptTarget.ES2022 }
	}).outputText;
	let interval: (() => void) | null = null;
	let destroy = () => {};
	const handlers = new Map<string, (...args: any[]) => void>();
	const connection = {
		on: vi.fn((name, callback) => handlers.set(name, callback)),
		off: vi.fn((name) => handlers.delete(name))
	};
	const unsubscribe = vi.fn();
	const context: any = {
		isOwnedSubAgentChat,
		getChatById: fetchChat,
		$user: { id: 'owner' },
		$subAgentViewer: { parentId: 'parent', userId: 'owner', selectedId: id, scopeRevision: 1 },
		localStorage: { token: 'private-token' },
		onMount: () => {},
		onDestroy: (callback: () => void) => {
			destroy = callback;
		},
		tick: async () => {},
		requestAnimationFrame: (callback: () => void) => {
			callback();
		},
		setInterval: vi.fn((callback) => {
			interval = callback;
			return 1;
		}),
		clearInterval: vi.fn(() => {
			interval = null;
		}),
		socket: {
			subscribe: (callback) => {
				callback(connection);
				return unsubscribe;
			}
		}
	};
	const viewer = runInNewContext(
		code +
			`\nparentChatId='parent'; mounted=true; visible=true;
		({refresh, startTracking, getSelection:()=>selection, isBusy:()=>busy,
		select:()=>syncSelection($subAgentViewer,$user?.id??'',parentChatId),
		setElement:(value)=>element=value, hide:()=>visible=false});`,
		context
	);
	return {
		...viewer,
		context,
		connection,
		unsubscribe,
		destroy: () => destroy(),
		poll: () => interval?.(),
		event: (name: string, value?: any) => handlers.get(name)?.(value)
	};
}

describe('selected native sidebar controller', () => {
	it('fetches only the selected child through the authenticated native API and does not overlap', async () => {
		let resolve: (chat: unknown) => void = () => {};
		const fetchChat = vi.fn(
			() =>
				new Promise((done) => {
					resolve = done;
				})
		);
		const viewer = controller(fetchChat);
		viewer.select();
		void viewer.refresh(viewer.getSelection());
		expect(fetchChat).toHaveBeenCalledTimes(1);
		expect(fetchChat).toHaveBeenCalledWith('private-token', id);
		resolve(saved);
		await settle();
		expect(viewer.getSelection().chat).toEqual(saved);
	});
	it('queues a child switch behind a stale request without rendering the old child', async () => {
		const resolvers: ((chat: unknown) => void)[] = [];
		const fetchChat = vi.fn(() => new Promise((resolve) => resolvers.push(resolve)));
		const viewer = controller(fetchChat);
		viewer.select();
		const old = viewer.getSelection();
		viewer.context.$subAgentViewer.selectedId = secondId;
		viewer.select();
		expect(fetchChat).toHaveBeenCalledTimes(1);
		resolvers[0](saved);
		await settle();
		expect(old.chat).toBeNull();
		expect(fetchChat).toHaveBeenLastCalledWith('private-token', secondId);
		resolvers[1]({ ...saved, id: secondId });
		await settle();
		expect(viewer.getSelection().chat.id).toBe(secondId);
	});
	it('denies unauthenticated fetches and unrelated records, with retry after failure', async () => {
		const fetchChat = vi.fn().mockResolvedValue({ ...saved, user_id: 'other' });
		const viewer = controller(fetchChat);
		viewer.context.localStorage.token = '';
		viewer.select();
		await settle();
		expect(fetchChat).not.toHaveBeenCalled();
		expect(viewer.getSelection().error).toContain('unavailable');
		viewer.context.localStorage.token = 'private-token';
		await viewer.refresh(viewer.getSelection());
		expect(viewer.getSelection().chat).toBeNull();
		fetchChat.mockResolvedValue(saved);
		await viewer.refresh(viewer.getSelection());
		expect(viewer.getSelection().error).toBe('');
		expect(viewer.getSelection().chat).toEqual(saved);
	});
	it.each(['user', 'parent', 'destroy', 'hide'])(
		'ignores late fetch after %s changes',
		async (change) => {
			let resolve: (chat: unknown) => void = () => {};
			const viewer = controller(
				vi.fn(
					() =>
						new Promise((done) => {
							resolve = done;
						})
				)
			);
			viewer.select();
			const entry = viewer.getSelection();
			if (change === 'user') viewer.context.$user = { id: 'other' };
			if (change === 'parent') viewer.context.$subAgentViewer.parentId = 'other';
			if (change === 'destroy') viewer.destroy();
			if (change === 'hide') viewer.hide();
			resolve(saved);
			await settle();
			expect(entry.chat).toBeNull();
		}
	);
	it('preserves scrollback and follows output only when already at the bottom', async () => {
		const viewer = controller(vi.fn().mockResolvedValue(saved));
		viewer.select();
		await settle();
		const element = { scrollTop: 100, scrollHeight: 1000, clientHeight: 300 };
		viewer.setElement(element);
		await viewer.refresh(viewer.getSelection());
		expect(element.scrollTop).toBe(100);
		element.scrollTop = 690;
		await viewer.refresh(viewer.getSelection());
		expect(element.scrollTop).toBe(1000);
	});
	it('polls running chats, queues socket/reconnect work, final-reconciles and detaches when hidden', async () => {
		const fetchChat = vi.fn().mockResolvedValue(saved);
		const viewer = controller(fetchChat);
		viewer.select();
		await settle();
		const stop = viewer.startTracking();
		viewer.poll();
		await settle();
		const done = {
			...saved,
			chat: { history: { ...saved.chat.history, messages: { assistant: { done: true } } } }
		};
		fetchChat.mockResolvedValue(done);
		viewer.event('events', { chat_id: id });
		viewer.poll();
		await settle();
		viewer.poll(); // final reconciliation
		await settle();
		const calls = fetchChat.mock.calls.length;
		viewer.poll();
		await settle();
		expect(fetchChat).toHaveBeenCalledTimes(calls);
		viewer.event('events', { chat_id: 'unrelated' });
		viewer.poll();
		expect(fetchChat).toHaveBeenCalledTimes(calls);
		viewer.event('connect');
		viewer.poll();
		await settle();
		expect(fetchChat).toHaveBeenCalledTimes(calls + 1);
		viewer.hide();
		stop();
		viewer.poll();
		expect(viewer.unsubscribe).toHaveBeenCalledOnce();
		expect(viewer.connection.off).toHaveBeenCalledWith('events', expect.any(Function));
		expect(viewer.connection.off).toHaveBeenCalledWith('connect', expect.any(Function));
	});
	it('generic iframe forwards embed messages only from its own window, with that source, and has no sub-agent knowledge', () => {
		const source = readFileSync(
			new URL('../common/FullHeightIframe.svelte', import.meta.url),
			'utf8'
		);
		expect(source).not.toMatch(/subagent/i);
		const handler = source.match(/function onMessage\(e: MessageEvent\) \{[\s\S]*?\n\t\}/)![0];
		const code = ts.transpileModule(handler, {
			compilerOptions: { target: ts.ScriptTarget.ES2022 }
		}).outputText;
		const postMessage = vi.fn(),
			onEmbedMessage = vi.fn();
		const frameWindow = { postMessage };
		const onMessage = runInNewContext(code + ';onMessage;', {
			iframe: { contentWindow: frameWindow },
			onEmbedMessage
		});
		const event = { type: 'subagent:chats', chats: [] };
		onMessage({ source: {}, data: event });
		expect(onEmbedMessage).not.toHaveBeenCalled();
		onMessage({ source: frameWindow, data: event });
		expect(onEmbedMessage).toHaveBeenCalledWith(event, frameWindow);
		expect(postMessage).not.toHaveBeenCalled();
	});
	it('renders one native read-only child in both sidebar branches, not a modal or nested embed', () => {
		const viewer = readFileSync(new URL('./SubAgentChatViewer.svelte', import.meta.url), 'utf8');
		const response = readFileSync(
			new URL('./Messages/ResponseMessage.svelte', import.meta.url),
			'utf8'
		);
		const controls = readFileSync(new URL('./ChatControls.svelte', import.meta.url), 'utf8');
		expect(viewer).not.toMatch(/Modal|FullHeightIframe|chatId\.set/);
		expect(viewer.match(/<Messages\b/g)).toHaveLength(1);
		for (const flag of ['readOnly', 'compactPreview']) expect(viewer).toContain(`${flag}={true}`);
		for (const flag of ['editCodeBlock', 'allowDelete', 'autoScroll'])
			expect(viewer).toContain(`${flag}={false}`);
		expect(response).not.toContain('<SubAgentChatViewer');
		expect(response).toContain('onEmbedMessage={embedMessageHandler}');
		expect(controls.match(/<SubAgentChatViewer\b/g)).toHaveLength(2);
		expect(controls.match(/<SubAgentTabButton\b/g)).toHaveLength(2);
		expect(controls).not.toContain('>Sub-agents<');
	});
	it('open requests take sidebar precedence once and an existing terminal does not steal a user tab', () => {
		const source = readFileSync(new URL('./ChatControls.svelte', import.meta.url), 'utf8');
		const open = source.match(/\$: if \(showSubAgentsTab &&[\s\S]*?\n\t\}/)![0].replace('$:', '');
		const terminal = source
			.match(
				/\$: if \(\s*\$selectedTerminalId\s*&&\s*terminalFilesAvailable\s*&&[\s\S]*?\n\t\}/
			)![0]
			.replace('$:', '');
		const context: any = {
			showSubAgentsTab: true,
			$subAgentViewer: { openRevision: 1 },
			handledOpenRevision: 0,
			activeTab: 'overview',
			showArtifacts: { set: vi.fn() },
			showEmbeds: { set: vi.fn() },
			showCallOverlay: { set: vi.fn() },
			showControls: { set: vi.fn() },
			$selectedTerminalId: 'terminal',
			activatedTerminalId: 'terminal',
			terminalFilesAvailable: true
		};
		runInNewContext(open + terminal, context);
		expect(context.activeTab).toBe('subagents');
		for (const store of ['showArtifacts', 'showEmbeds', 'showCallOverlay'])
			expect(context[store].set).toHaveBeenCalledWith(false);
		expect(context.showControls.set).toHaveBeenCalledWith(true);
		context.activeTab = 'overview';
		runInNewContext(open + terminal, context);
		expect(context.activeTab).toBe('overview');
		expect(context.showControls.set).toHaveBeenCalledTimes(1);
		context.$selectedTerminalId = 'new-terminal';
		runInNewContext(terminal, context);
		expect(context.activeTab).toBe('files');
	});
	it('compiles the affected Svelte components for client and SSR without executing SSR scope state', () => {
		for (const file of [
			'ChatControls.svelte',
			'../../ext/SubAgentTabButton.svelte',
			'SubAgentChatViewer.svelte',
			'../common/Select.svelte',
			'Messages/ResponseMessage.svelte'
		]) {
			const source = readFileSync(new URL(`./${file}`, import.meta.url), 'utf8');
			for (const generate of ['client', 'server'] as const) {
				expect(() => compile(source, { filename: file, generate })).not.toThrow();
			}
		}
	});
	it('keeps the tab visible for an empty saved or new active owner scope in both layouts', () => {
		const source = readFileSync(new URL('./ChatControls.svelte', import.meta.url), 'utf8');
		const expression = source.match(/\$: showSubAgentsTab =[\s\S]*?;/)![0].replace('$:', '');
		for (const parentId of ['', id]) {
			const context = {
				showSubAgentsTab: false,
				scopeMounted: true,
				chatId: parentId,
				chatUser: null,
				$activeChatId: parentId,
				$user: { id: 'owner' },
				$subAgentViewer: { parentId, userId: 'owner', catalog: [], discovery: 'ready' }
			};
			runInNewContext(expression, context);
			expect(context.showSubAgentsTab).toBe(true);
			for (const changes of [
				{ scopeMounted: false },
				{ $user: null },
				{ chatUser: { id: 'other' } },
				{ $activeChatId: 'other' },
				{ chatId: 'other' },
				{ $subAgentViewer: { parentId, userId: 'other', catalog: [] } }
			]) {
				const changed = { ...context, ...changes };
				runInNewContext(expression, changed);
				expect(changed.showSubAgentsTab).toBe(false);
			}
		}
		expect(source.match(/\{#if showSubAgentsTab\}/g)).toHaveLength(2);
	});
	it('uses the house Select with UUID values, title labels and accessible read-only context', () => {
		const viewer = readFileSync(new URL('./SubAgentChatViewer.svelte', import.meta.url), 'utf8');
		expect(viewer).toContain("import Select from '$lib/components/common/Select.svelte'");
		expect(viewer).not.toMatch(/<select\b|<option\b/);
		expect(viewer).toContain('value: chat.chatId, label: chat.title');
		expect(viewer).toContain('onChange={selectSubAgentChat}');
		expect(viewer).toContain('<span class="sr-only">Sub-agent · Read-only: </span>');
		expect(viewer).toContain('No sub-agents have been used in this chat yet.');
		expect(viewer).toContain('Loading sub-agent catalog');
		expect(viewer).toContain('Retry catalog');
		expect(viewer).toContain('on:click={refreshSubAgentCatalog}');
	});
});
