<script lang="ts">
	export let active = false;
</script>

<button
	type="button"
	aria-pressed={active}
	class="px-2.5 py-1 text-sm rounded-lg transition whitespace-nowrap {active
		? 'bg-gray-100/40 dark:bg-gray-800/25 font-normal text-gray-700 dark:text-gray-200'
		: 'text-gray-500 dark:text-gray-400 hover:bg-gray-100/30 dark:hover:bg-gray-800/20 hover:text-gray-600 dark:hover:text-gray-300'}"
	on:click>Sub-agents</button
>
