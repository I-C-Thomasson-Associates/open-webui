import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { describe, expect, it, vi } from 'vitest';
import { isOwnedSubAgentChat, mergeSubAgentChats, parseSubAgentChat } from './subAgentViewer';

function controller(fetchChat: (...args: any[]) => any) {
	const source = readFileSync(new URL('./SubAgentChatViewer.svelte', import.meta.url), 'utf8');
	const script = source
		.match(/<script lang="ts">([\s\S]*?)<\/script>/)![1]
		.replace(/\bimport[\s\S]*?from\s+['"][^'"]+['"];?/g, '')
		.replace(/\bexport\s+/g, '');
	const code = ts.transpileModule(script, {
		compilerOptions: { target: ts.ScriptTarget.ES2022 }
	}).outputText;
	return runInNewContext(
		code +
			`\nparentChatId='parent'; mounted=true; ({handleEmbedMessage, closePane, refresh, getPanes:()=>panes});`,
		{
			isOwnedSubAgentChat,
			mergeSubAgentChats,
			parseSubAgentChat,
			getChatById: fetchChat,
			$user: { id: 'owner' },
			localStorage: { token: 'private-token' },
			onMount: () => {},
			onDestroy: () => {},
			tick: async () => {},
			requestAnimationFrame: (callback: () => void) => {
				callback();
			},
			setInterval,
			clearInterval
		}
	);
}
const id = '12345678-1234-1234-1234-123456789abc';
const open = { type: 'subagent:open-chat', chatId: id, title: 'Task' };
const saved = {
	id,
	user_id: 'owner',
	meta: { internal: true, type: 'subagent', source: 'ai_team_delegate', parent_chat_id: 'parent' },
	chat: { history: { currentId: 'assistant', messages: { assistant: { done: false } } } }
};
const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe('native viewer controller', () => {
	it('fetches only on click, deduplicates, and keeps credentials at the native API', async () => {
		const fetchChat = vi.fn().mockResolvedValue(saved);
		const viewer = controller(fetchChat);
		viewer.handleEmbedMessage({ type: 'subagent:chats', chats: [open] });
		expect(fetchChat).not.toHaveBeenCalled();
		viewer.handleEmbedMessage(open);
		viewer.handleEmbedMessage(open);
		await settle();
		expect(viewer.getPanes()).toHaveLength(1);
		expect(fetchChat).toHaveBeenCalledTimes(1);
		expect(fetchChat).toHaveBeenCalledWith('private-token', id);
		expect(viewer.getPanes()[0].chat).toEqual(saved);
	});
	it('rejects unrelated chats before rendering', async () => {
		const viewer = controller(vi.fn().mockResolvedValue({ ...saved, user_id: 'other' }));
		viewer.handleEmbedMessage(open);
		await settle();
		expect(viewer.getPanes()[0].chat).toBeNull();
		expect(viewer.getPanes()[0].error).toContain('unavailable');
	});
	it('ignores a late fetch after a pane closes', async () => {
		let resolve: (chat: unknown) => void = () => {};
		const viewer = controller(
			vi.fn(
				() =>
					new Promise((done) => {
						resolve = done;
					})
			)
		);
		viewer.handleEmbedMessage(open);
		const pane = viewer.getPanes()[0];
		viewer.closePane(pane);
		resolve(saved);
		await settle();
		expect(viewer.getPanes()).toHaveLength(0);
		expect(pane.chat).toBeNull();
	});
	it('preserves scrollback and follows output when already at the bottom', async () => {
		const viewer = controller(vi.fn().mockResolvedValue(saved));
		viewer.handleEmbedMessage(open);
		await settle();
		const pane = viewer.getPanes()[0];
		pane.element = { scrollTop: 100, scrollHeight: 1000, clientHeight: 300 };
		await viewer.refresh(pane);
		expect(pane.element.scrollTop).toBe(100);
		pane.element.scrollTop = 690;
		await viewer.refresh(pane);
		expect(pane.element.scrollTop).toBe(1000);
	});
	it('accepts bridge events only from the exact originating iframe', () => {
		const source = readFileSync(
			new URL('../common/FullHeightIframe.svelte', import.meta.url),
			'utf8'
		);
		const handler = source.match(/function onMessage\(e: MessageEvent\) \{[\s\S]*?\n\t\}/)![0];
		const code = ts.transpileModule(handler, {
			compilerOptions: { target: ts.ScriptTarget.ES2022 }
		}).outputText;
		const postMessage = vi.fn(),
			onEmbedMessage = vi.fn(() => true);
		const frameWindow = { postMessage };
		const onMessage = runInNewContext(code + ';onMessage;', {
			iframe: { contentWindow: frameWindow },
			onEmbedMessage
		});
		onMessage({ source: {}, data: open });
		expect(onEmbedMessage).not.toHaveBeenCalled();
		onMessage({ source: frameWindow, data: { type: 'subagent:chats', chats: [] } });
		expect(postMessage).toHaveBeenCalledWith({ type: 'subagent:viewer-ready' }, '*');
	});
});
