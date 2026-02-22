<script lang="ts">
	import { getContext } from 'svelte';
	import { goto } from '$app/navigation';
	import { marked } from 'marked';
	import DOMPurify from 'dompurify';
	import { toast } from 'svelte-sonner';

	import { deleteScheduleRunById } from '$lib/apis/schedules';

	import Clipboard from '$lib/components/icons/Clipboard.svelte';
	import Check from '$lib/components/icons/Check.svelte';
	import ChevronLeft from '$lib/components/icons/ChevronLeft.svelte';
	import GarbageBin from '$lib/components/icons/GarbageBin.svelte';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import Badge from '$lib/components/common/Badge.svelte';
	import ConfirmDialog from '$lib/components/common/ConfirmDialog.svelte';

	const i18n = getContext('i18n');

	export let schedule;
	export let runs = [];

	let selectedRun = runs.length > 0 ? runs[0] : null;
	let contentCopied = false;
	let showDeleteConfirm = false;
	let runToDelete = null;

	const renderMarkdown = (text: string) => {
		if (!text) return '';
		return DOMPurify.sanitize(marked.parse(text));
	};

	const formatDate = (timestamp) => {
		if (!timestamp) return 'N/A';
		return new Date(timestamp * 1000).toLocaleString();
	};

	const renderRelativeDate = (timestamp) => {
		if (!timestamp) return '';
		const date = new Date(timestamp * 1000);
		const now = new Date();
		const diffMs = now.getTime() - date.getTime();
		const diffMins = Math.floor(diffMs / 60000);
		const diffHours = Math.floor(diffMs / 3600000);
		const diffDays = Math.floor(diffMs / 86400000);

		if (diffMins < 1) return 'just now';
		if (diffMins < 60) return `${diffMins}m ago`;
		if (diffHours < 24) return `${diffHours}h ago`;
		if (diffDays < 7) return `${diffDays}d ago`;
		return date.toLocaleDateString();
	};

	const copyContent = () => {
		if (selectedRun?.result) {
			navigator.clipboard.writeText(selectedRun.result);
			contentCopied = true;
			setTimeout(() => (contentCopied = false), 2000);
		}
	};

	const downloadMarkdown = () => {
		if (!selectedRun?.result) return;
		const blob = new Blob([selectedRun.result], { type: 'text/markdown' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `schedule-report-${selectedRun.id}.md`;
		a.click();
		URL.revokeObjectURL(url);
	};

	const downloadPdf = async () => {
		if (!selectedRun?.result) return;
		const htmlContent = renderMarkdown(selectedRun.result);
		const printWindow = window.open('', '_blank');
		if (!printWindow) {
			toast.error($i18n.t('Popup blocked. Please allow popups to download PDF.'));
			return;
		}
		printWindow.document.write(`<!DOCTYPE html>
<html>
<head>
<title>Schedule Report - ${selectedRun.id}</title>
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

	const confirmDeleteRun = (run) => {
		runToDelete = run;
		showDeleteConfirm = true;
	};

	const deleteRun = async () => {
		if (!runToDelete) return;
		try {
			await deleteScheduleRunById(localStorage.token, runToDelete.id);
			runs = runs.filter((r) => r.id !== runToDelete.id);
			if (selectedRun?.id === runToDelete.id) {
				selectedRun = runs.length > 0 ? runs[0] : null;
			}
			toast.success($i18n.t('Run deleted'));
		} catch (err) {
			toast.error($i18n.t('Failed to delete run'));
		}
		runToDelete = null;
	};
</script>

<div class="flex flex-col h-full px-1">
	<!-- Header -->
	<div class="flex items-center gap-3 mt-1.5 mb-3 px-0.5">
		<button
			class="p-1 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-850 transition"
			on:click={() => goto('/workspace/schedules')}
		>
			<ChevronLeft className="size-4" />
		</button>
		<div class="flex-1">
			<div class="flex items-center gap-2">
				<div class="text-xl font-medium">{schedule.name}</div>
				<span
					class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium {schedule.is_active
						? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
						: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'}"
				>
					{schedule.is_active ? $i18n.t('Active') : $i18n.t('Inactive')}
				</span>
			</div>
			<div class="text-xs text-gray-500">
				{schedule.model_id} • {schedule.frequency}
			</div>
		</div>
		<a
			class="px-3 py-1.5 text-xs font-medium rounded-xl bg-gray-100 hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 transition"
			href={`/workspace/schedules/edit?id=${encodeURIComponent(schedule.id)}`}
		>
			{$i18n.t('Edit')}
		</a>
	</div>

	<!-- Split pane: Runs list (left) + Report content (right) -->
	<div
		class="flex-1 flex flex-col md:flex-row gap-4 overflow-hidden pb-6 bg-white dark:bg-gray-900 rounded-3xl border border-gray-100/30 dark:border-gray-850/30 p-4"
	>
		<!-- Left: Runs list -->
		<div class="hidden md:flex md:flex-col w-72 shrink-0 overflow-hidden">
			<div class="flex items-center justify-between mb-2 shrink-0">
				<div class="text-gray-500 text-xs">{$i18n.t('Run History')}</div>
				<div class="text-gray-400 text-xs">{runs.length} {$i18n.t('runs')}</div>
			</div>

			{#if runs.length > 0}
				<div class="space-y-0 flex-1 overflow-y-auto">
					{#each runs as run}
						<!-- svelte-ignore a11y-no-static-element-interactions -->
						<div
							class="flex-1 w-full text-left px-3.5 py-2 mb-1 rounded-2xl transition group cursor-pointer
								{selectedRun?.id === run.id
								? 'bg-gray-100/50 dark:bg-gray-850/50'
								: 'hover:bg-gray-100/50 dark:hover:bg-gray-850/50'}"
							on:click={() => (selectedRun = run)}
							on:keydown={(e) => { if (e.key === 'Enter') selectedRun = run; }}
							role="button"
							tabindex="0"
						>
							<!-- Status + date -->
							<div class="flex items-center gap-2 mb-1">
								<span
									class="w-1.5 h-1.5 rounded-full shrink-0 {run.status === 'completed'
										? 'bg-green-500'
										: run.status === 'failed'
											? 'bg-red-500'
											: run.status === 'running'
												? 'bg-blue-500'
												: 'bg-gray-400'}"
								></span>
								<div class="text-xs text-gray-900 dark:text-white truncate flex-1">
									{run.status === 'completed'
										? $i18n.t('Completed')
										: run.status === 'failed'
											? $i18n.t('Failed')
											: run.status === 'running'
												? $i18n.t('Running')
												: $i18n.t('Pending')}
								</div>
								{#if selectedRun?.id === run.id}
									<Badge type="info" content={$i18n.t('Selected')} />
								{/if}
								<button
									class="md:invisible md:group-hover:visible p-0.5 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700 transition text-gray-400 hover:text-red-500"
									on:click|stopPropagation={() => confirmDeleteRun(run)}
									title={$i18n.t('Delete run')}
								>
									<GarbageBin className="size-3.5" />
								</button>
							</div>

							<!-- Timestamp -->
							<div class="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400">
								<span class="shrink-0">{renderRelativeDate(run.created_at)}</span>
								<span>•</span>
								<span class="truncate">{formatDate(run.created_at)}</span>
							</div>
						</div>
					{/each}
				</div>
			{:else}
				<div class="text-xs text-gray-400 text-center py-6 italic">
					{$i18n.t('No runs yet')}
				</div>
			{/if}
		</div>

		<!-- Mobile: Runs dropdown + delete button (visible on small screens) -->
		<div class="md:hidden">
			{#if runs.length > 0}
				<div class="flex items-center gap-2">
					<select
						class="flex-1 text-sm rounded-xl bg-gray-50 dark:bg-gray-850 border border-gray-200 dark:border-gray-700 px-3 py-2"
						on:change={(e) => {
							selectedRun = runs.find((r) => r.id === e.target.value) || null;
						}}
						value={selectedRun?.id}
					>
						{#each runs as run}
							<option value={run.id}>
								{run.status} — {formatDate(run.created_at)}
							</option>
						{/each}
					</select>
					{#if selectedRun}
						<button
							class="p-2 rounded-xl bg-gray-50 dark:bg-gray-850 border border-gray-200 dark:border-gray-700 text-gray-400 hover:text-red-500 transition"
							on:click={() => confirmDeleteRun(selectedRun)}
							title={$i18n.t('Delete run')}
						>
							<GarbageBin className="size-4" />
						</button>
					{/if}
				</div>
			{:else}
				<div class="text-xs text-gray-400 text-center py-4 italic">
					{$i18n.t('No runs yet')}
				</div>
			{/if}
		</div>

		<!-- Right: Report content -->
		<div class="flex-1 flex flex-col min-h-0 overflow-hidden">
			{#if selectedRun}
				<div class="flex items-center justify-between mb-1 shrink-0">
					<div class="flex items-center gap-2">
						<div class="text-gray-500 text-xs">
							{$i18n.t('Report')}
						</div>
						<span
							class="text-xs text-gray-500 font-mono bg-gray-100 dark:bg-gray-800 px-1.5 rounded"
						>
							{selectedRun.id.slice(0, 7)}
						</span>
						<span
							class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium {selectedRun.status ===
							'completed'
								? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
								: selectedRun.status === 'failed'
									? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
									: selectedRun.status === 'running'
										? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
										: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'}"
						>
							{selectedRun.status}
						</span>
					</div>

					<div class="flex items-center gap-2">
						{#if selectedRun.result}
							<button
								class="px-2.5 py-1 text-xs font-medium rounded-lg bg-gray-100 hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 transition"
								on:click={downloadMarkdown}
							>
								{$i18n.t('Download MD')}
							</button>
							<button
								class="px-2.5 py-1 text-xs font-medium rounded-lg bg-gray-100 hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 transition"
								on:click={downloadPdf}
							>
								{$i18n.t('Download PDF')}
							</button>
						{/if}
					</div>
				</div>

				<!-- Timestamps -->
				<div class="flex items-center gap-4 mb-2 text-xs text-gray-500 shrink-0">
					<span>{$i18n.t('Started')}: {formatDate(selectedRun.started_at)}</span>
					<span>{$i18n.t('Completed')}: {formatDate(selectedRun.completed_at)}</span>
				</div>

				<!-- Content container with copy button -->
				<div class="relative flex-1 min-h-0">
					{#if selectedRun.result}
						<!-- Copy button -->
						<div class="absolute top-2 right-2 z-10">
							<button
								class="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition"
								on:click={copyContent}
							>
								{#if contentCopied}
									<Check className="size-4 text-green-500" />
								{:else}
									<Clipboard className="size-4 text-gray-500" />
								{/if}
							</button>
						</div>
						<!-- Scrollable report content -->
						<div
							class="bg-gray-50 dark:bg-gray-900 rounded-xl px-4 py-3 border border-gray-100/50 dark:border-gray-850/50 h-full overflow-y-auto prose dark:prose-invert max-w-none"
						>
							{@html renderMarkdown(selectedRun.result)}
						</div>
					{:else if selectedRun.status === 'running'}
						<div class="flex items-center justify-center h-full">
							<div class="flex items-center gap-2 text-sm text-gray-500">
								<Spinner className="size-4" />
								{$i18n.t('Run in progress...')}
							</div>
						</div>
					{:else if selectedRun.status === 'failed'}
						<div
							class="bg-red-50 dark:bg-red-900/20 rounded-xl px-4 py-3 border border-red-100/50 dark:border-red-900/50 h-full overflow-y-auto"
						>
							<div class="text-sm text-red-700 dark:text-red-300">
								{$i18n.t('This run failed. No report was generated.')}
							</div>
						</div>
					{:else}
						<div class="flex items-center justify-center h-full">
							<div class="text-sm text-gray-400 italic">
								{$i18n.t('No report content available')}
							</div>
						</div>
					{/if}
				</div>
			{:else}
				<div class="flex items-center justify-center h-full">
					<div class="text-center">
						<div class="text-3xl mb-3">📄</div>
						<div class="text-sm text-gray-500">
							{runs.length > 0
								? $i18n.t('Select a run to view its report')
								: $i18n.t('No runs yet. Trigger a run from the schedules list.')}
						</div>
					</div>
				</div>
			{/if}
		</div>
	</div>
</div>

<ConfirmDialog
	bind:show={showDeleteConfirm}
	title={$i18n.t('Delete run?')}
	on:confirm={() => {
		deleteRun();
	}}
>
	<div class="text-sm text-gray-500">
		{$i18n.t('Are you sure you want to delete this run? This action cannot be undone.')}
	</div>
</ConfirmDialog>
