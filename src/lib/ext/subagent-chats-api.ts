import { WEBUI_API_BASE_URL } from '$lib/constants';

export async function getSubAgentChats(token: string, parentId: string, signal: AbortSignal) {
	if (!token) throw new Error('Unavailable');
	const response = await fetch(`${WEBUI_API_BASE_URL}/ext/subagent-chats/${parentId}`, {
		method: 'GET',
		headers: { Accept: 'application/json', authorization: `Bearer ${token}` },
		signal
	});
	if (!response.ok) throw new Error('Unavailable');
	return response.json() as Promise<unknown>;
}
