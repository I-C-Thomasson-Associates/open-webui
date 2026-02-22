<script lang="ts">
	import { getContext } from 'svelte';
	import { marked } from 'marked';
	import DOMPurify from 'dompurify';
	import Modal from '$lib/components/common/Modal.svelte';

	const i18n = getContext('i18n');

	export let show = false;
	export let run = null;

	const formatDate = (timestamp) => {
		if (!timestamp) return 'N/A';
		return new Date(timestamp * 1000).toLocaleString();
	};

	const renderMarkdown = (text: string) => {
		if (!text) return '';
		return DOMPurify.sanitize(marked.parse(text));
	};
</script>

<Modal bind:show size="lg">
	<div>
		<div class="flex justify-between dark:text-gray-300 px-5 pt-4 pb-2">
			<div class="text-lg font-medium self-center">{$i18n.t('Run Report')}</div>
			<button
				class="self-center"
				on:click={() => {
					show = false;
				}}
			>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					viewBox="0 0 20 20"
					fill="currentColor"
					class="w-5 h-5"
				>
					<path
						d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"
					/>
				</svg>
			</button>
		</div>

		{#if run}
			<div class="px-5 pb-5">
				<div class="flex flex-col gap-3">
					<div class="flex items-center gap-2">
						<span class="text-sm font-medium text-gray-500 dark:text-gray-400"
							>{$i18n.t('Status')}:</span
						>
						<span
							class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {run.status ===
							'completed'
								? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
								: run.status === 'failed'
									? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
									: run.status === 'running'
										? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
										: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'}"
						>
							{run.status}
						</span>
					</div>

					<div class="flex items-center gap-2">
						<span class="text-sm font-medium text-gray-500 dark:text-gray-400"
							>{$i18n.t('Started')}:</span
						>
						<span class="text-sm">{formatDate(run.started_at)}</span>
					</div>

					<div class="flex items-center gap-2">
						<span class="text-sm font-medium text-gray-500 dark:text-gray-400"
							>{$i18n.t('Completed')}:</span
						>
						<span class="text-sm">{formatDate(run.completed_at)}</span>
					</div>

					{#if run.result}
						<div class="mt-2">
							<div
								class="mt-1 p-4 bg-gray-50 dark:bg-gray-900 rounded-xl text-sm prose dark:prose-invert max-w-none max-h-[60vh] overflow-y-auto"
							>
								{@html renderMarkdown(run.result)}
							</div>
						</div>
					{/if}
				</div>
			</div>
		{/if}
	</div>
</Modal>
