<script lang="ts">
	import { onDestroy, onMount, tick } from 'svelte';
	import { getChatById } from '$lib/apis/chats';
	import { socket, user } from '$lib/stores';
	import Modal from '$lib/components/common/Modal.svelte';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import Messages from './Messages.svelte';
	import {
		isOwnedSubAgentChat,
		mergeSubAgentChats,
		parseSubAgentChat,
		type SubAgentChat
	} from './subAgentViewer';
	export let parentChatId: string;
	type Pane = SubAgentChat & {
		chat: any;
		busy: boolean;
		error: string;
		element: HTMLDivElement | null;
	};
	let catalog: SubAgentChat[] = [];
	let panes: Pane[] = [];
	let show = false;
	let mounted = false;
	let stopTracking: (() => void) | null = null;
	let ownerId = '';
	const noop = () => {};
	const current = (pane: Pane) => mounted && show && panes.includes(pane);
	const running = (pane: Pane) =>
		pane.chat?.chat?.history?.messages?.[pane.chat?.chat?.history?.currentId]?.done === false;
	const pending = new Set<Pane>();

	export function handleEmbedMessage(value: unknown): boolean {
		if (!value || typeof value !== 'object') return false;
		const data = value as Record<string, unknown>;
		if (data.type === 'subagent:chats' && Array.isArray(data.chats) && data.chats.length <= 64) {
			const chats = data.chats.map(parseSubAgentChat);
			if (chats.some((chat) => !chat)) return false;
			catalog = mergeSubAgentChats(catalog, chats as SubAgentChat[]);
			return true;
		}
		if (data.type === 'subagent:open-chat') {
			const chat = parseSubAgentChat(data);
			if (!chat) return false;
			catalog = mergeSubAgentChats(catalog, [chat]);
			return openChat(chat);
		}
		return false;
	}
	function openChat(chat: SubAgentChat): boolean {
		show = true;
		if (panes.some((pane) => pane.chatId === chat.chatId)) return true;
		// ponytail: cap concurrent previews at eight; revisit for larger comparison batches.
		if (panes.length >= 8) return false;
		const pane: Pane = { ...chat, chat: null, busy: false, error: '', element: null };
		panes = [...panes, pane];
		void refresh(pane);
		return true;
	}
	async function refresh(pane: Pane) {
		if (!current(pane) || pane.busy) return;
		pane.busy = true;
		panes = [...panes];
		const owner = $user?.id ?? '';
		try {
			if (!owner || !parentChatId) throw new Error('Unavailable');
			const chat = await getChatById(localStorage.token, pane.chatId);
			if (!current(pane) || owner !== $user?.id) return;
			if (!isOwnedSubAgentChat(chat, pane.chatId, owner, parentChatId))
				throw new Error('Unavailable');
			const element = pane.element;
			const top = element?.scrollTop ?? 0;
			const follow =
				!pane.chat || !element || element.scrollHeight - top - element.clientHeight < 80;
			pane.chat = chat;
			pane.error = '';
			panes = [...panes];
			await tick();
			// Messages rebuilds streaming history on the next animation frame.
			await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
			if (current(pane) && pane.element)
				pane.element.scrollTop = follow ? pane.element.scrollHeight : top;
		} catch {
			if (current(pane)) {
				pane.chat = null;
				pane.error = 'This sub-agent chat is unavailable. Use Refresh to retry.';
			}
		} finally {
			pane.busy = false;
			if (current(pane)) panes = [...panes];
		}
	}
	function closePane(pane: Pane) {
		pending.delete(pane);
		panes = panes.filter((entry) => entry !== pane);
	}
	$: if (!show) {
		pending.clear();
		panes = [];
	}
	$: if (mounted && show && !stopTracking) stopTracking = startTracking();
	$: if (!show && stopTracking) {
		stopTracking();
		stopTracking = null;
	}
	$: if (($user?.id ?? '') !== ownerId) {
		ownerId = $user?.id ?? '';
		show = false;
	}
	onMount(() => {
		mounted = true;
	});
	onDestroy(() => {
		mounted = false;
		stopTracking?.();
	});
	function startTracking() {
		// A short delay lets the chat API overlay stream content after socket emission.
		const timer = setInterval(() => {
			for (const pane of panes)
				if (pending.has(pane) || running(pane)) {
					if (!pane.busy) {
						pending.delete(pane);
						void refresh(pane);
					}
				}
		}, 1000);
		const onEvent = (event: any) => {
			for (const pane of panes) if (pane.chatId === event?.chat_id) pending.add(pane);
		};
		const onConnect = () => {
			for (const pane of panes) pending.add(pane);
		};
		let connected: any = null;
		const unsubscribe = socket.subscribe((value) => {
			connected?.off('events', onEvent);
			connected?.off('connect', onConnect);
			connected = value;
			connected?.on('events', onEvent);
			connected?.on('connect', onConnect);
		});
		return () => {
			clearInterval(timer);
			unsubscribe();
			connected?.off('events', onEvent);
			connected?.off('connect', onConnect);
		};
	}
</script>

{#if catalog.length}
	<button
		type="button"
		class="my-2 rounded-lg px-3 py-1.5 text-sm font-medium hover:bg-black/5 dark:hover:bg-white/5"
		on:click={() => {
			show = true;
		}}>Sub-agent chats ({catalog.length})</button
	>
{/if}
<Modal bind:show size="3xl">
	<div class="modal-content p-4">
		<div class="flex items-center justify-between gap-3">
			<h2 class="text-lg font-semibold">
				Sub-agent chats <span class="text-sm font-normal text-gray-500">Read-only</span>
			</h2>
			<button
				type="button"
				class="rounded-lg px-3 py-2 hover:bg-black/5 dark:hover:bg-white/5"
				on:click={() => {
					show = false;
				}}>Close</button
			>
		</div>
		<div
			class="my-3 flex max-h-28 flex-wrap gap-2 overflow-y-auto"
			aria-label="Available sub-agent chats"
		>
			{#each catalog as chat (chat.chatId)}
				<button
					type="button"
					class="max-w-full truncate rounded-lg border px-3 py-1.5 text-sm dark:border-gray-700"
					aria-pressed={panes.some((pane) => pane.chatId === chat.chatId)}
					disabled={panes.length >= 8 && !panes.some((pane) => pane.chatId === chat.chatId)}
					on:click={() => openChat(chat)}>{chat.title}</button
				>
			{/each}
		</div>
		{#if !panes.length}<p class="py-12 text-center text-gray-500">
				Select a sub-agent to view its conversation.
			</p>{/if}
		<div
			class="grid max-h-[75dvh] gap-3 overflow-y-auto {panes.length > 1 ? 'md:grid-cols-2' : ''}"
		>
			{#each panes as pane (pane.chatId)}
				<section
					class="min-w-0 overflow-hidden rounded-xl border dark:border-gray-700"
					aria-label={pane.title}
				>
					<div class="flex items-center gap-2 border-b p-3 dark:border-gray-700">
						<h3 class="min-w-0 flex-1 truncate text-sm font-medium" title={pane.title}>
							{pane.title}
						</h3>
						<a
							class="text-xs underline"
							href={`/c/${pane.chatId}`}
							target="_blank"
							rel="noopener noreferrer">Open full chat</a
						>
						<button
							type="button"
							class="rounded px-2 py-1 text-xs hover:bg-black/5 dark:hover:bg-white/5"
							disabled={pane.busy}
							on:click={() => refresh(pane)}>Refresh</button
						>
						<button
							type="button"
							class="rounded px-2 py-1 hover:bg-black/5 dark:hover:bg-white/5"
							aria-label={`Close ${pane.title}`}
							on:click={() => closePane(pane)}>×</button
						>
					</div>
					<div
						bind:this={pane.element}
						id={`subagent-viewer-${parentChatId}-${pane.chatId}`}
						class="h-[55dvh] overflow-y-auto @container"
					>
						{#if pane.error}<p role="alert" class="p-6 text-sm text-gray-500">{pane.error}</p>
						{:else if !pane.chat}<div class="flex justify-center p-8"><Spinner /></div>
						{:else if pane.chat.chat?.history?.currentId}
							<Messages
								chatId={pane.chatId}
								user={$user}
								history={pane.chat.chat.history}
								selectedModels={pane.chat.chat.models ?? []}
								atSelectedModel={null}
								prompt=""
								readOnly={true}
								compactPreview={true}
								editCodeBlock={false}
								allowDelete={false}
								autoScroll={false}
								messagesCount={null}
								messagesContainerId={`subagent-viewer-${parentChatId}-${pane.chatId}`}
								className="flex w-full pt-3 [&_.message-listitem]:!px-3 [&_.message-listitem]:!max-w-none"
								sendMessage={noop}
								continueResponse={noop}
								regenerateResponse={noop}
								mergeResponses={noop}
								chatActionHandler={noop}
							/>
						{:else}<p class="p-6 text-sm text-gray-500">No messages yet.</p>{/if}
					</div>
				</section>
			{/each}
		</div>
	</div>
</Modal>
