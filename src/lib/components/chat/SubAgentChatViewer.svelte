<script lang="ts">
	import { onDestroy, onMount, tick } from 'svelte';
	import { getChatById } from '$lib/apis/chats';
	import { socket, user } from '$lib/stores';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import Messages from './Messages.svelte';
	import { isOwnedSubAgentChat, selectSubAgentChat, subAgentViewer } from './subAgentViewer';

	export let parentChatId: string;
	export let visible = false;
	type Selection = {
		id: string;
		parentId: string;
		ownerId: string;
		scopeRevision: number;
		chat: any;
		error: string;
	};
	let selection: Selection | null = null;
	let element: HTMLDivElement | null = null;
	let mounted = false;
	let busy = false;
	let pending = false;
	let stopTracking: (() => void) | null = null;
	const noop = () => {};
	const current = (entry: Selection) =>
		mounted &&
		visible &&
		selection === entry &&
		entry.parentId === parentChatId &&
		entry.ownerId === $user?.id &&
		entry.parentId === $subAgentViewer.parentId &&
		entry.ownerId === $subAgentViewer.userId &&
		entry.id === $subAgentViewer.selectedId &&
		entry.scopeRevision === $subAgentViewer.scopeRevision;
	const running = (entry: Selection) =>
		entry.chat?.chat?.history?.messages?.[entry.chat?.chat?.history?.currentId]?.done === false;

	function syncSelection(state: typeof $subAgentViewer, ownerId: string, parentId: string) {
		if (!ownerId || state.userId !== ownerId || state.parentId !== parentId || !state.selectedId) {
			selection = null;
			pending = false;
			return;
		}
		if (selection?.id === state.selectedId && selection?.scopeRevision === state.scopeRevision)
			return;
		selection = {
			id: state.selectedId,
			parentId,
			ownerId,
			scopeRevision: state.scopeRevision,
			chat: null,
			error: ''
		};
		if (element) element.scrollTop = 0;
		pending = true;
		if (mounted && visible) void refresh(selection);
	}
	$: syncSelection($subAgentViewer, $user?.id ?? '', parentChatId);
	$: if (mounted && visible && !stopTracking) {
		stopTracking = startTracking();
		pending = true;
		if (selection) void refresh(selection);
	}
	$: if (!visible && stopTracking) {
		stopTracking();
		stopTracking = null;
		pending = false;
	}

	async function refresh(entry: Selection) {
		if (!current(entry) || busy) return;
		busy = true;
		pending = false;
		const wasRunning = running(entry);
		try {
			const token = localStorage.token;
			if (!token) throw new Error('Unavailable');
			const chat = await getChatById(token, entry.id);
			if (!current(entry)) return;
			if (!isOwnedSubAgentChat(chat, entry.id, entry.ownerId, entry.parentId))
				throw new Error('Unavailable');
			const top = element?.scrollTop ?? 0;
			const follow =
				!entry.chat || !element || element.scrollHeight - top - element.clientHeight < 80;
			entry.chat = chat;
			entry.error = '';
			selection = entry;
			// Reconcile once more after the API reports completion, including late persisted metadata.
			if (wasRunning && !running(entry)) pending = true;
			await tick();
			// Messages rebuilds history on the next animation frame.
			await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
			if (current(entry) && element) element.scrollTop = follow ? element.scrollHeight : top;
		} catch {
			if (current(entry)) {
				entry.chat = null;
				entry.error = 'This sub-agent chat is unavailable. Use Refresh to retry.';
				selection = entry;
			}
		} finally {
			busy = false;
			// A selection change queues behind the old request rather than overlapping it.
			if (selection && selection !== entry && pending && current(selection))
				void refresh(selection);
		}
	}

	onMount(() => {
		mounted = true;
	});
	onDestroy(() => {
		mounted = false;
		stopTracking?.();
	});
	function startTracking() {
		const timer = setInterval(() => {
			if (selection && (pending || running(selection)) && !busy) void refresh(selection);
		}, 1000);
		const onEvent = (event: any) => {
			if (selection?.id === event?.chat_id) pending = true;
		};
		const onConnect = () => {
			pending = true;
		};
		let connected: any = null;
		const unsubscribe = socket.subscribe((value) => {
			connected?.off('events', onEvent);
			connected?.off('connect', onConnect);
			connected = value;
			connected?.on('events', onEvent);
			connected?.on('connect', onConnect);
			onConnect();
		});
		return () => {
			clearInterval(timer);
			unsubscribe();
			connected?.off('events', onEvent);
			connected?.off('connect', onConnect);
		};
	}
</script>

<section class="flex h-full min-h-0 flex-col" aria-label="Sub-agent conversation">
	<div class="shrink-0 space-y-2 border-b p-3 dark:border-gray-800">
		<label for="subagent-selector" class="block text-xs font-medium text-gray-500"
			>Sub-agent · Read-only</label
		>
		<select
			id="subagent-selector"
			class="w-full rounded-lg bg-gray-50 p-2 text-sm dark:bg-gray-850"
			value={$subAgentViewer.selectedId}
			on:change={(event) => selectSubAgentChat(event.currentTarget.value)}
		>
			{#each $subAgentViewer.catalog as chat (chat.chatId)}
				<option value={chat.chatId}>{chat.title}</option>
			{/each}
		</select>
		{#if selection}
			<div class="flex items-center justify-between gap-2 text-xs">
				<a class="underline" href={`/c/${selection.id}`} target="_blank" rel="noopener noreferrer"
					>Open full chat</a
				>
				<button
					type="button"
					class="rounded px-2 py-1 hover:bg-black/5 dark:hover:bg-white/5"
					disabled={busy}
					on:click={() => selection && refresh(selection)}>Refresh</button
				>
			</div>
		{/if}
	</div>
	<div
		bind:this={element}
		id={`subagent-viewer-${parentChatId}`}
		class="min-h-0 flex-1 overflow-y-auto @container"
		aria-busy={busy}
	>
		{#if selection?.error}<p role="alert" class="p-6 text-sm text-gray-500">{selection.error}</p>
		{:else if selection && !selection.chat}<div
				role="status"
				aria-label="Loading sub-agent chat"
				class="flex justify-center p-8"
			>
				<Spinner />
			</div>
		{:else if selection?.chat?.chat?.history?.currentId}
			{#key selection.id}
				<Messages
					chatId={selection.id}
					user={$user}
					history={selection.chat.chat.history}
					selectedModels={selection.chat.chat.models ?? []}
					atSelectedModel={null}
					prompt=""
					readOnly={true}
					compactPreview={true}
					editCodeBlock={false}
					allowDelete={false}
					autoScroll={false}
					messagesCount={null}
					messagesContainerId={`subagent-viewer-${parentChatId}`}
					className="flex w-full pt-3 [&_.message-listitem]:!px-3 [&_.message-listitem]:!max-w-none"
					sendMessage={noop}
					continueResponse={noop}
					regenerateResponse={noop}
					mergeResponses={noop}
					chatActionHandler={noop}
				/>
			{/key}
		{:else}<p class="p-6 text-sm text-gray-500">No messages yet.</p>{/if}
	</div>
</section>
