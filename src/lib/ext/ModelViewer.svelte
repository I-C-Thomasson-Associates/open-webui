<script lang="ts">
	import { getContext, onDestroy, onMount } from 'svelte';
	import { get } from 'svelte/store';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import {
		applyModelViewerCommand,
		getViewerToken,
		loadViewerRuntime,
		modelViewerCommands,
		newCommands,
		type ModelViewerRef
	} from './modelViewer';

	export let ref: ModelViewerRef;

	const i18n: any = getContext('i18n');
	let container: HTMLDivElement;
	let viewer: any = null;
	let status: 'loading' | 'ready' | 'error' = 'loading';
	let error = '';
	// Only commands sent after this tab opened; ones sent while it loads still apply.
	let lastSeq = get(modelViewerCommands).at(-1)?.seq ?? 0;
	let applying: Promise<unknown> = Promise.resolve();
	let destroyed = false;
	// Tokens live only in memory (modelViewer.ts and Autodesk's viewer), never in chat or tab state.
	const fetchToken = () => getViewerToken(localStorage.token, ref);

	const open = async () => {
		status = 'loading';
		error = '';
		try {
			const first = await fetchToken();
			const Viewing = await loadViewerRuntime(fetchToken);
			if (destroyed) return;
			if (!viewer) {
				viewer = new Viewing.GuiViewer3D(container);
				if (viewer.start() > 0) {
					viewer = null;
					throw new Error('WebGL is not available in this browser');
				}
			}
			const doc: any = await new Promise((resolve, reject) =>
				Viewing.Document.load(`urn:${first.urn}`, resolve, (code: number, message: string) =>
					reject(new Error(message || `Model could not be loaded (${code})`))
				)
			);
			if (destroyed) return;
			await viewer.loadDocumentNode(doc, doc.getRoot().getDefaultGeometry());
			status = 'ready';
		} catch (e) {
			status = 'error';
			error = e instanceof Error ? e.message : String(e);
		}
	};

	$: if (status === 'ready' && viewer) {
		const next = newCommands($modelViewerCommands, lastSeq, ref.versionId);
		lastSeq = next.lastSeq;
		// In order: a search-based command must not finish after the next one.
		for (const command of next.commands)
			applying = applying
				.then(() => applyModelViewerCommand(viewer, command))
				.catch((e) => console.error('Model viewer command', e));
	}

	onMount(open);
	onDestroy(() => {
		destroyed = true;
		viewer?.finish();
		viewer = null;
	});
</script>

<div class="relative flex h-full w-full flex-col">
	<div class="relative min-h-0 flex-1" bind:this={container}></div>
	{#if status !== 'ready'}
		<div
			class="absolute inset-0 flex flex-col items-center justify-center gap-3 p-6 text-center text-sm text-gray-500"
			role="status"
		>
			{#if status === 'loading'}
				<Spinner />
				<span>{$i18n.t('Loading {{name}}…', { name: ref.name ?? 'model' })}</span>
			{:else}
				<span>{error}</span>
				<button
					class="rounded-lg bg-gray-100 px-3 py-1.5 text-gray-800 hover:bg-gray-200 dark:bg-gray-850 dark:text-gray-200 dark:hover:bg-gray-800"
					on:click={open}>{$i18n.t('Retry')}</button
				>
			{/if}
		</div>
	{/if}
</div>
