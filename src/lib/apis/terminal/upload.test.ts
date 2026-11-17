import { afterEach, describe, expect, it, vi } from 'vitest';
import { config } from '$lib/stores';
import { uploadToTerminal } from './index';

const target = {
	selector: 'tether:device',
	baseUrl: '/api/v1/terminals/tether:device',
	key: 'token',
	system: false,
	context: { chatId: 'chat-1', modelId: null }
};
const ok = () => new Response(JSON.stringify({ path: '/home/a.txt', size: 1 }), { status: 200 });

describe('uploadToTerminal', () => {
	afterEach(() => vi.unstubAllGlobals());

	it('falls back to multipart upload when the runtime has no streaming endpoint', async () => {
		config.set({ features: { enable_tool_servers: true } } as any);
		const fetch = vi
			.fn()
			.mockResolvedValueOnce(new Response('{}', { status: 404 }))
			.mockResolvedValueOnce(ok());
		vi.stubGlobal('fetch', fetch);

		expect(await uploadToTerminal(target, '/home', new File(['a'], 'a.txt'))).toEqual({
			path: '/home/a.txt',
			size: 1
		});
		expect(fetch.mock.calls[0][0]).toContain('/files/upload-stream?');
		expect(fetch.mock.calls[1][0]).toBe(`${target.baseUrl}/files/upload?directory=%2Fhome`);
		expect(fetch.mock.calls[1][1].body).toBeInstanceOf(FormData);
		expect(fetch.mock.calls[1][1].headers['X-Session-Id']).toBe('chat-1');
	});

	it('does not retry other failures', async () => {
		config.set({ features: { enable_tool_servers: true } } as any);
		const fetch = vi.fn().mockResolvedValue(new Response('{"detail":"no"}', { status: 413 }));
		vi.stubGlobal('fetch', fetch);

		expect(await uploadToTerminal(target, '/home', new File(['a'], 'a.txt'))).toBeNull();
		expect(fetch).toHaveBeenCalledOnce();
	});
});
