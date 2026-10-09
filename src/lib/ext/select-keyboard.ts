/** Keyboard behavior stays local to the trigger and its portalled content. */
export function focusSelectOption(content: HTMLElement) {
	if (content.getAttribute('role') === 'dialog') {
		const search = Array.from(
			content.querySelectorAll<HTMLInputElement>('input:not([type="hidden"]), textarea, select')
		).find(
			(control) =>
				control.tabIndex >= 0 &&
				!control.disabled &&
				!control.closest('[hidden], [inert], [aria-disabled="true"]')
		);
		if (search) {
			search.focus();
			return;
		}
	}
	const options = selectOptions(content);
	const selected = options.find(
		(option) =>
			option.getAttribute('aria-checked') === 'true' ||
			option.getAttribute('aria-selected') === 'true'
	);
	(selected ?? options[0] ?? content).focus();
}

export function selectContentFocusout(
	event: FocusEvent,
	content: HTMLElement,
	trigger: HTMLElement,
	close: (restoreFocus: boolean) => void
) {
	if (
		content.getAttribute('role') === 'dialog' &&
		!content.contains(event.relatedTarget as Node) &&
		!trigger.contains(event.relatedTarget as Node)
	) {
		// The trigger and portal form one focus boundary, independent of click timing.
		setTimeout(() => {
			const active = content.ownerDocument.activeElement;
			if (content.isConnected && !content.contains(active) && !trigger.contains(active))
				close(false);
		}, 0);
	}
}

function selectOptions(content: HTMLElement): HTMLButtonElement[] {
	return Array.from(content.querySelectorAll<HTMLButtonElement>('button')).filter(
		(option) => !option.disabled && !option.closest('[hidden], [inert], [aria-disabled="true"]')
	);
}

export function selectTriggerKeydown(
	event: KeyboardEvent,
	trigger: HTMLElement,
	open: boolean,
	show: () => void,
	close: () => void
) {
	if (event.key === 'Escape' && open) {
		event.preventDefault();
		event.stopPropagation();
		close();
		return;
	}
	// A slotted clear button must retain its own native keyboard behavior.
	if (event.target !== trigger) return;
	if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
		event.preventDefault();
		event.stopPropagation();
		show();
	}
}

export function selectContentKeydown(
	event: KeyboardEvent,
	content: HTMLElement,
	trigger: HTMLElement,
	close: (restoreFocus: boolean) => void
) {
	if (event.key === 'Escape') {
		event.preventDefault();
		event.stopPropagation();
		close(true);
		return;
	}
	if (event.key === 'Tab') {
		if (content.getAttribute('role') === 'dialog') return;
		// Let the browser tab from the trigger, not from the portal at the end of body.
		trigger.focus();
		close(false);
		return;
	}
	const options = selectOptions(content);
	const index = options.indexOf(event.target as HTMLButtonElement);
	// Leave caret navigation and activation in custom search inputs untouched.
	if (index === -1 && event.target !== content) return;
	let next: number;
	switch (event.key) {
		case 'ArrowDown':
			next = (index + 1) % options.length;
			break;
		case 'ArrowUp':
			next = (index - 1 + options.length) % options.length;
			break;
		case 'Home':
			next = 0;
			break;
		case 'End':
			next = options.length - 1;
			break;
		default:
			return;
	}
	event.preventDefault();
	event.stopPropagation();
	options[next]?.focus();
}
