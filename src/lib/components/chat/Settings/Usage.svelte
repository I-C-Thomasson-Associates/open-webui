<script lang="ts">
	import { getContext, onMount } from 'svelte';
	import { getUserUsage, type UserUsage } from '$lib/apis/usage';

	const i18n = getContext('i18n');

	let loaded = false;
	let usage: UserUsage | null = null;

	$: percent = usage?.percent ?? null;
	$: barWidth = percent !== null ? Math.min(percent, 100) : 0;
	$: barColor =
		barWidth >= 90 ? 'bg-[#da3e44]' : barWidth >= 50 ? 'bg-amber-400/80' : 'bg-emerald-500/80';

	const formatResetDate = (timestamp: number) => {
		return new Date(timestamp * 1000).toLocaleDateString(undefined, {
			month: 'long',
			day: 'numeric'
		});
	};

	onMount(async () => {
		usage = await getUserUsage(localStorage.token).catch(() => null);
		loaded = true;
	});
</script>

<div id="tab-usage" class="flex flex-col space-y-3 text-sm">
	<div>
		<div>
			<div class=" mb-2.5 flex items-center justify-between">
				<div class="text-sm font-medium">{$i18n.t('Monthly AI Usage')}</div>
				{#if usage?.tier}
					<div
						class="px-2 py-0.5 rounded-full text-xs text-gray-500 bg-gray-50 dark:bg-gray-850"
					>
						{usage.tier}
					</div>
				{/if}
			</div>

			{#if !loaded}
				<div class="text-xs text-gray-500">{$i18n.t('Loading...')}</div>
			{:else if usage?.exempt}
				<div class="text-xs text-gray-500">
					{$i18n.t('No usage limits apply to your account.')}
				</div>
			{:else if !usage || percent === null}
				<div class="text-xs text-gray-500">
					{$i18n.t('Usage information is currently unavailable.')}
				</div>
				<div class="mt-2 text-xs text-gray-500">
					{$i18n.t('To be upgraded to the next usage tier, please contact your manager.')}
				</div>
			{:else}
				<div class="flex items-center gap-3">
					<div class="flex-1 h-2 rounded-full bg-gray-100 dark:bg-gray-800 overflow-hidden">
						<div
							class="h-full rounded-full {barColor} transition-all"
							style="width: {barWidth}%"
						></div>
					</div>
					<div class="text-xs font-medium w-10 text-right">{percent}%</div>
				</div>
				<div class="mt-2 text-xs text-gray-500">
					{#if percent >= 100}
						{$i18n.t("You've reached your monthly usage limit.")}
					{:else if usage.tier}
						{$i18n.t("You've used {{percent}}% of your monthly AI usage on {{tier}}.", {
							percent,
							tier: usage.tier
						})}
					{:else}
						{$i18n.t("You've used {{percent}}% of your monthly AI usage.", { percent })}
					{/if}
					{$i18n.t('Resets {{date}}.', { date: formatResetDate(usage.reset_at) })}
				</div>
				<div class="mt-2 text-xs text-gray-500">
					{$i18n.t('To be upgraded to the next usage tier, please contact your manager.')}
				</div>
			{/if}
		</div>
	</div>
</div>
