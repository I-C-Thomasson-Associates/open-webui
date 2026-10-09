import { describe, expect, it } from 'vitest';
import { isOwnedSubAgentChat, mergeSubAgentChats, parseSubAgentChat } from './subAgentViewer';
const id = '12345678-1234-1234-1234-123456789abc';
describe('sub-agent viewer boundaries', () => {
	it('rejects URL injection and oversized labels', () => {
		expect(parseSubAgentChat({ chatId: '../other', title: 'Task' })).toBeNull();
		expect(parseSubAgentChat({ chatId: id, title: 'x'.repeat(201) })).toBeNull();
		expect(parseSubAgentChat({ chatId: id, title: ' Task ' })).toEqual({
			chatId: id,
			title: 'Task'
		});
	});
	it('requires owner, child identity, internal provenance and originating parent', () => {
		const chat = {
			id,
			user_id: 'user',
			meta: {
				internal: true,
				type: 'subagent',
				source: 'ai_team_delegate',
				parent_chat_id: 'parent'
			}
		};
		expect(isOwnedSubAgentChat(chat, id, 'user', 'parent')).toBe(true);
		for (const changed of [
			{ ...chat, user_id: 'other' },
			{ ...chat, id: 'other' },
			...['internal', 'type', 'source', 'parent_chat_id'].map((key) => ({
				...chat,
				meta: { ...chat.meta, [key]: 'other' }
			}))
		])
			expect(isOwnedSubAgentChat(changed, id, 'user', 'parent')).toBe(false);
	});
	it('merges snapshots without removing or duplicating known children', () => {
		const chat = { chatId: id, title: 'Task' };
		expect(mergeSubAgentChats([chat], [])).toEqual([chat]);
		expect(mergeSubAgentChats([chat], [chat])).toEqual([chat]);
	});
});
