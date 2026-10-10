<script lang="ts">
	import { flyAndScale } from '$lib/utils/transitions';
	import { onMount, tick } from 'svelte';
	import { v4 as uuidv4 } from 'uuid';
	import {
		focusSelectOption,
		selectContentFocusout,
		selectContentKeydown,
		selectTriggerKeydown
	} from '$lib/ext/select-keyboard';
	import DropdownMenu from '$lib/components/common/DropdownMenu.svelte';

	/** Currently selected value */
	export let value = '';

	/** Items array: { value: string, label: string }[] */
	export let items = [];

	/** Placeholder text when no value is selected */
	export let placeholder = '';

	/** Callback when value changes */
	export let onChange: (value: string) => void = () => {};

	/** CSS classes for the trigger button */
	export let triggerClass = '';

	/** CSS classes for the label inside the trigger */
	export let labelClass = '';

	/** CSS classes for the dropdown content container */
	export let contentClass = 'min-w-[10.625rem]';

	/** Max height for the dropdown content */
	export let maxHeight = '18rem';

	/** CSS classes for each item button */
	export let itemClass =
		'flex h-[1.6875rem] w-full cursor-pointer items-center gap-2 rounded-xl bg-transparent px-2 text-[0.8125rem] hover:bg-gray-50/40 hover:text-gray-900 dark:hover:bg-gray-800/40 dark:hover:text-gray-100';

	/** Alignment of the dropdown: 'start' | 'end' */
	export let align = 'start';

	/** Side to open on: 'bottom' | 'top' */
	export let side = 'bottom';

	/** Callback when dropdown closes */
	export let onClose: () => void = () => {};

	export let open = false;

	let triggerEl;
	let contentEl;
	let contentId: string;
	let wasOpen = false;
	let restoreOnClose = true;

	onMount(() => {
		contentId = `select-${uuidv4()}`;
	});

	$: if (open !== wasOpen) {
		wasOpen = open;
		if (open) focusContent();
		else {
			if (restoreOnClose && contentEl?.contains(document.activeElement)) triggerEl?.focus();
			restoreOnClose = true;
			onClose();
		}
	}

	$: selectedLabel = items.find((i) => i.value === value)?.label ?? placeholder;

	/** Svelte action: moves the node to document.body (portal) */
	function portal(node) {
		document.body.appendChild(node);
		return {
			destroy() {
				if (node.parentNode) {
					node.parentNode.removeChild(node);
				}
			}
		};
	}

	function positionContent() {
		if (!triggerEl || !contentEl) return;
		const rect = triggerEl.getBoundingClientRect();

		contentEl.style.position = 'fixed';
		contentEl.style.zIndex = '9999';
		contentEl.style.minWidth = `${rect.width}px`;

		const contentHeight = contentEl.offsetHeight || 0;
		const spaceBelow = window.innerHeight - rect.bottom - 4;
		const spaceAbove = rect.top - 4;

		let openAbove = side === 'top';
		if (side === 'bottom' && spaceBelow < contentHeight && spaceAbove > spaceBelow) {
			openAbove = true;
		} else if (side === 'top' && spaceAbove < contentHeight && spaceBelow > spaceAbove) {
			openAbove = false;
		}

		if (openAbove) {
			contentEl.style.bottom = `${window.innerHeight - rect.top + 4}px`;
			contentEl.style.top = 'auto';
		} else {
			contentEl.style.top = `${rect.bottom + 4}px`;
			contentEl.style.bottom = 'auto';
		}

		const contentWidth = contentEl.offsetWidth || 0;

		if (align === 'end') {
			let right = window.innerWidth - rect.right;
			if (right + contentWidth > window.innerWidth) {
				right = window.innerWidth - contentWidth - 16;
			}
			contentEl.style.right = `${Math.max(16, right)}px`;
			contentEl.style.left = 'auto';
		} else {
			let left = rect.left;
			if (left + contentWidth + 16 > window.innerWidth) {
				left = window.innerWidth - contentWidth - 16;
			}
			contentEl.style.left = `${Math.max(16, left)}px`;
			contentEl.style.right = 'auto';
		}
	}

	async function focusContent() {
		await tick();
		if (!open || !contentEl) return;
		positionContent();
		focusSelectOption(contentEl);
	}

	function close(restoreFocus = true) {
		if (!open) return;
		restoreOnClose = restoreFocus;
		open = false;
		if (restoreFocus) triggerEl?.focus();
	}

	function toggleOpen() {
		if (open) close();
		else open = true;
	}

	function handleWindowClick(event) {
		if (!open) return;
		if (triggerEl?.contains(event.target)) return;
		if (contentEl?.contains(event.target)) return;
		close(false);
	}

	export function selectItem(item) {
		value = item.value;
		close();
		onChange(value);
	}
</script>

<svelte:window
	on:click={handleWindowClick}
	on:scroll|capture={positionContent}
	on:resize={positionContent}
/>

<button
	bind:this={triggerEl}
	class="focus-ring {triggerClass}"
	type="button"
	aria-expanded={open}
	aria-haspopup={$$slots.default ? 'dialog' : 'menu'}
	aria-controls={open ? contentId : undefined}
	id={contentId ? `${contentId}-trigger` : undefined}
	on:click={toggleOpen}
	on:focusout={(event) => {
		if (open && contentEl) selectContentFocusout(event, contentEl, triggerEl, close);
	}}
	on:keydown={(event) =>
		selectTriggerKeydown(
			event,
			triggerEl,
			open,
			() => {
				if (open) focusContent();
				else open = true;
			},
			() => close()
		)}
>
	<slot name="trigger" {selectedLabel} {open}>
		<span class={labelClass}>
			{selectedLabel}
		</span>
	</slot>
</button>

{#if open}
	<div
		use:portal
		bind:this={contentEl}
		id={contentId}
		role={$$slots.default ? 'dialog' : 'menu'}
		aria-labelledby={contentId ? `${contentId}-trigger` : undefined}
		tabindex="-1"
		on:keydown|capture={(event) => {
			if (open) selectContentKeydown(event, contentEl, triggerEl, close);
		}}
		on:focusout={(event) => {
			if (open) selectContentFocusout(event, contentEl, triggerEl, close);
		}}
		transition:flyAndScale
	>
		<DropdownMenu className={contentClass} style={`max-height: ${maxHeight}; overflow-y: auto;`}>
			<slot {open} {selectItem}>
				{#each items as item}
					<button
						class="focus-ring {itemClass}"
						type="button"
						role="menuitemradio"
						aria-checked={value === item.value}
						tabindex="-1"
						on:click={() => selectItem(item)}
					>
						<slot name="item" {item} selected={value === item.value}>
							{item.label}
						</slot>
					</button>
				{/each}
			</slot>
		</DropdownMenu>
	</div>
{/if}
