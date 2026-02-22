<script lang="ts">
	import { getContext } from 'svelte';
	import { marked } from 'marked';
	import DOMPurify from 'dompurify';
	import { toast } from 'svelte-sonner';
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

	const downloadMarkdown = () => {
		if (!run?.result) return;
		const blob = new Blob([run.result], { type: 'text/markdown' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `schedule-report-${run.id}.md`;
		a.click();
		URL.revokeObjectURL(url);
	};

	const downloadPdf = async () => {
		if (!run?.result) return;
		const htmlContent = renderMarkdown(run.result);
		const printWindow = window.open('', '_blank');
		if (!printWindow) {
			toast.error($i18n.t('Popup blocked. Please allow popups to download PDF.'));
			return;
		}
		printWindow.document.write(`<!DOCTYPE html>
<html>
<head>
<title>Schedule Report - ${run.id}</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #333; }
h1, h2, h3 { margin-top: 1.5em; }
code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
pre { background: #f4f4f4; padding: 16px; border-radius: 6px; overflow-x: auto; }
hr { border: none; border-top: 1px solid #ddd; margin: 2em 0; }
</style>
</head>
<body>${htmlContent}</body>
</html>`);
		printWindow.document.close();
		printWindow.onload = () => {
			printWindow.print();
		};
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
							<div class="flex items-center justify-between mb-2">
								<div class="text-sm font-medium text-gray-500 dark:text-gray-400">
									{$i18n.t('Report')}
								</div>
								<div class="flex gap-2">
									<button
										class="px-2.5 py-1 text-xs font-medium rounded-lg bg-gray-100 hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 transition"
										on:click={downloadMarkdown}
									>
										{$i18n.t('Download Markdown')}
									</button>
									<button
										class="px-2.5 py-1 text-xs font-medium rounded-lg bg-gray-100 hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 transition"
										on:click={downloadPdf}
									>
										{$i18n.t('Download PDF')}
									</button>
								</div>
							</div>
							<div
								class="p-4 bg-gray-50 dark:bg-gray-900 rounded-xl text-sm prose dark:prose-invert max-w-none max-h-[60vh] overflow-y-auto"
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
