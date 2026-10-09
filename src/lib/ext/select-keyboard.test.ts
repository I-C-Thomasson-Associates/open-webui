import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { compile } from 'svelte/compiler';
import {
	focusSelectOption,
	selectContentFocusout,
	selectContentKeydown,
	selectTriggerKeydown
} from './select-keyboard';

// No DOM emulator is installed. These doubles exercise the exported event handlers,
// including native cancellation; they do not claim to test Svelte mounting or layout.
function fixture(dialog = false) {
	let active: unknown;
	const button = (checked = false, disabled = false, hidden = false) => ({
		disabled,
		tabIndex: 0,
		contains(this: unknown, node: unknown) {
			return this === node;
		},
		getAttribute: (name: string) => (name === 'aria-checked' ? String(checked) : null),
		closest: () => (hidden ? {} : null),
		focus: vi.fn(function (this: unknown) {
			active = this;
		})
	});
	const buttons = [
		button(),
		button(true),
		button(),
		button(false, true),
		button(false, false, true)
	];
	const trigger = button();
	const input = { ...button(), tabIndex: 0 };
	const content = {
		isConnected: true,
		ownerDocument: {
			get activeElement() {
				return active;
			}
		},
		getAttribute: (name: string) => (name === 'role' ? (dialog ? 'dialog' : 'menu') : null),
		querySelectorAll: (selector: string) => (selector === 'button' ? buttons : [input]),
		contains: (node: unknown) =>
			node === content || node === input || buttons.some((button) => button === node),
		focus: vi.fn(() => {
			active = content;
		})
	};
	const close = vi.fn((restore: boolean) => {
		if (restore) trigger.focus();
	});
	const key = (name: string, target: unknown, shiftKey = false) => {
		const event = new Event('keydown', { bubbles: true, cancelable: true });
		Object.defineProperties(event, {
			key: { value: name },
			target: { value: target },
			shiftKey: { value: shiftKey }
		});
		return event as KeyboardEvent;
	};
	return {
		buttons,
		input,
		outside: button(),
		trigger: trigger as unknown as HTMLElement,
		content: content as unknown as HTMLElement,
		close,
		key,
		active: () => active
	};
}

afterEach(() => {
	vi.useRealTimers();
});

describe('shared Select keyboard behavior', () => {
	it('focuses the selected enabled option, then first available, then empty content', () => {
		const f = fixture();
		focusSelectOption(f.content);
		expect(f.active()).toBe(f.buttons[1]);
		f.buttons[1].disabled = true;
		focusSelectOption(f.content);
		expect(f.active()).toBe(f.buttons[0]);
		f.buttons.forEach((button) => (button.disabled = true));
		focusSelectOption(f.content);
		expect(f.active()).toBe(f.content);
	});

	it.each(['ArrowDown', 'ArrowUp'])(
		'opens from trigger %s and consumes only its own event',
		(key) => {
			const f = fixture();
			const show = vi.fn(() => focusSelectOption(f.content));
			const event = f.key(key, f.trigger);
			selectTriggerKeydown(event, f.trigger, false, show, () => f.close(true));
			expect(show).toHaveBeenCalledOnce();
			expect(f.active()).toBe(f.buttons[1]);
			expect(event.defaultPrevented).toBe(true);
			expect(event.cancelBubble).toBe(true);
			selectTriggerKeydown(f.key(key, {}), f.trigger, false, show, () => f.close(true));
			expect(show).toHaveBeenCalledOnce();
		}
	);

	it('navigates Arrow keys/Home/End, wraps, and skips disabled or hidden buttons', () => {
		const f = fixture();
		focusSelectOption(f.content);
		for (const [key, index] of [
			['ArrowDown', 2],
			['ArrowDown', 0],
			['ArrowUp', 2],
			['Home', 0],
			['End', 2]
		] as const) {
			const event = f.key(key, f.active());
			selectContentKeydown(event, f.content, f.trigger, f.close);
			expect(f.active()).toBe(f.buttons[index]);
			expect(event.defaultPrevented).toBe(true);
		}
	});

	it.each(['Enter', ' '])('leaves native button selection via %s untouched', (key) => {
		const f = fixture();
		const event = f.key(key, f.buttons[1]);
		selectContentKeydown(event, f.content, f.trigger, f.close);
		expect(event.defaultPrevented).toBe(false);
		expect(event.cancelBubble).toBe(false);
		expect(f.close).not.toHaveBeenCalled();
	});

	it('consumes Escape before the Drawer window listener and restores trigger focus', () => {
		const f = fixture();
		const drawerClose = vi.fn();
		const event = f.key('Escape', f.buttons[1]);
		selectContentKeydown(event, f.content, f.trigger, f.close);
		// Model the bubbling boundary: Drawer receives only events not stopped locally.
		if (!event.cancelBubble) drawerClose();
		expect(drawerClose).not.toHaveBeenCalled();
		expect(event.defaultPrevented).toBe(true);
		expect(f.close).toHaveBeenCalledWith(true);
		expect(f.active()).toBe(f.trigger);
	});

	it('only consumes trigger Escape while this Select is open', () => {
		const f = fixture();
		const event = f.key('Escape', f.trigger);
		selectTriggerKeydown(event, f.trigger, false, vi.fn(), () => f.close(true));
		expect(event.defaultPrevented).toBe(false);
		expect(f.close).not.toHaveBeenCalled();
		selectTriggerKeydown(event, f.trigger, true, vi.fn(), () => f.close(true));
		expect(event.defaultPrevented).toBe(true);
		expect(event.cancelBubble).toBe(true);
		expect(f.active()).toBe(f.trigger);
	});

	it('also consumes Escape from a slotted trigger clear button', () => {
		const f = fixture();
		const event = f.key('Escape', {});
		selectTriggerKeydown(event, f.trigger, true, vi.fn(), () => f.close(true));
		expect(event.defaultPrevented).toBe(true);
		expect(event.cancelBubble).toBe(true);
		expect(f.close).toHaveBeenCalledWith(true);
	});

	it.each([false, true])(
		'Tab (shift=%s) closes and leaves native traversal at the trigger',
		(shift) => {
			const f = fixture();
			const event = f.key('Tab', f.buttons[1], shift);
			selectContentKeydown(event, f.content, f.trigger, f.close);
			expect(f.active()).toBe(f.trigger);
			expect(f.close).toHaveBeenCalledWith(false);
			expect(event.defaultPrevented).toBe(false);
		}
	);

	it('preserves custom search caret keys, but Escape still closes from the search input', () => {
		const f = fixture();
		const input = {};
		for (const key of ['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter', ' ']) {
			const event = f.key(key, input);
			selectContentKeydown(event, f.content, f.trigger, f.close);
			expect(event.defaultPrevented).toBe(false);
		}
		selectContentKeydown(f.key('Escape', input), f.content, f.trigger, f.close);
		expect(f.close).toHaveBeenCalledWith(true);
	});

	it('uses native custom-slot buttons without requiring option roles', () => {
		const f = fixture();
		f.buttons.forEach((button) => (button.getAttribute = () => null));
		focusSelectOption(f.content);
		expect(f.active()).toBe(f.buttons[0]);
		selectContentKeydown(f.key('End', f.buttons[0]), f.content, f.trigger, f.close);
		expect(f.active()).toBe(f.buttons[2]);
	});

	it('focuses custom search even when results are empty, without changing native tab indices', () => {
		const f = fixture(true);
		focusSelectOption(f.content);
		expect(f.active()).toBe(f.input);
		expect(f.buttons.map((button) => button.tabIndex)).toEqual([0, 0, 0, 0, 0]);
		f.buttons.length = 0;
		focusSelectOption(f.content);
		expect(f.active()).toBe(f.input);
		expect(f.input.tabIndex).toBe(0);
	});

	it('skips a disabled or negative-tabindex search control on opening', () => {
		const f = fixture(true);
		f.input.disabled = true;
		focusSelectOption(f.content);
		expect(f.active()).toBe(f.buttons[1]);
		f.input.disabled = false;
		f.input.tabIndex = -1;
		focusSelectOption(f.content);
		expect(f.active()).toBe(f.buttons[1]);
	});

	it.each([
		['search to first result', false, 'search', 0],
		['first result back to search', true, 0, 'search'],
		['first result to next result', false, 0, 1],
		['next result to previous result', true, 1, 0]
	] as const)('preserves native internal Tab: %s', (_name, shift, from, to) => {
		const f = fixture(true);
		const source = from === 'search' ? f.input : f.buttons[from];
		const destination = to === 'search' ? f.input : f.buttons[to];
		source.focus();
		const event = f.key('Tab', source, shift);
		selectContentKeydown(event, f.content, f.trigger, f.close);
		expect(f.active()).toBe(source);
		expect(event.defaultPrevented).toBe(false);
		expect(event.cancelBubble).toBe(false);
		// Simulate only the browser's focus move, not its tab-order algorithm.
		destination.focus();
		selectContentFocusout(
			{ relatedTarget: destination } as unknown as FocusEvent,
			f.content,
			f.trigger,
			f.close
		);
		expect(f.active()).toBe(destination);
		expect(f.close).not.toHaveBeenCalled();
	});

	it.each([false, true])(
		'closes at a dialog traversal boundary (shift=%s) without stealing focus',
		(shift) => {
			vi.useFakeTimers();
			const f = fixture(true);
			const source = shift ? f.input : f.buttons[2];
			source.focus();
			const event = f.key('Tab', source, shift);
			selectContentKeydown(event, f.content, f.trigger, f.close);
			expect(event.defaultPrevented).toBe(false);
			const outside = f.outside;
			outside.focus();
			selectContentFocusout(
				{ relatedTarget: outside } as unknown as FocusEvent,
				f.content,
				f.trigger,
				f.close
			);
			vi.runAllTimers();
			expect(f.close).toHaveBeenCalledWith(false);
			expect(f.active()).toBe(outside);
		}
	);

	it('does not close after focus returns inside during an exit or after content is removed', () => {
		vi.useFakeTimers();
		const f = fixture(true);
		selectContentFocusout({ relatedTarget: null } as FocusEvent, f.content, f.trigger, f.close);
		f.input.focus();
		vi.runAllTimers();
		expect(f.close).not.toHaveBeenCalled();
		selectContentFocusout({ relatedTarget: null } as FocusEvent, f.content, f.trigger, f.close);
		f.trigger.focus();
		Object.assign(f.content, { isConnected: false });
		vi.runAllTimers();
		expect(f.close).not.toHaveBeenCalled();
	});

	it('custom search Escape remains consumed and restores trigger focus', () => {
		const f = fixture(true);
		f.input.focus();
		const event = f.key('Escape', f.input);
		selectContentKeydown(event, f.content, f.trigger, f.close);
		expect(event.defaultPrevented).toBe(true);
		expect(event.cancelBubble).toBe(true);
		expect(f.active()).toBe(f.trigger);
	});

	it('leaves custom search caret and native activation keys untouched', () => {
		const f = fixture(true);
		f.input.focus();
		for (const key of ['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter', ' ']) {
			const event = f.key(key, f.input);
			selectContentKeydown(event, f.content, f.trigger, f.close);
			expect(event.defaultPrevented).toBe(false);
			expect(f.active()).toBe(f.input);
		}
		expect(f.close).not.toHaveBeenCalled();
	});

	it('empty results still allow native Tab to exit the search without restoring trigger focus', () => {
		vi.useFakeTimers();
		const f = fixture(true);
		f.buttons.length = 0;
		focusSelectOption(f.content);
		const event = f.key('Tab', f.input);
		selectContentKeydown(event, f.content, f.trigger, f.close);
		expect(event.defaultPrevented).toBe(false);
		f.outside.focus();
		selectContentFocusout({ relatedTarget: null } as FocusEvent, f.content, f.trigger, f.close);
		vi.runAllTimers();
		expect(f.close).toHaveBeenCalledWith(false);
		expect(f.active()).toBe(f.outside);
	});

	it('focusout then timer then a delayed trigger click closes instead of reopening', () => {
		vi.useFakeTimers();
		const f = fixture(true);
		let open = true;
		const close = vi.fn(() => {
			open = false;
		});
		f.input.focus();
		f.trigger.focus();
		selectContentFocusout(
			{ relatedTarget: f.trigger } as unknown as FocusEvent,
			f.content,
			f.trigger,
			close
		);
		vi.runAllTimers();
		expect(open).toBe(true);
		expect(close).not.toHaveBeenCalled();
		// Select's trigger click uses this toggle; model mouseup after the timer.
		if (open) close();
		else open = true;
		expect(open).toBe(false);
		expect(close).toHaveBeenCalledOnce();
	});

	it('keyboard focus may enter the trigger, but leaving both trigger and content closes', () => {
		vi.useFakeTimers();
		const f = fixture(true);
		f.input.focus();
		const shiftTab = f.key('Tab', f.input, true);
		selectContentKeydown(shiftTab, f.content, f.trigger, f.close);
		expect(shiftTab.defaultPrevented).toBe(false);
		f.trigger.focus();
		selectContentFocusout(
			{ relatedTarget: f.trigger } as unknown as FocusEvent,
			f.content,
			f.trigger,
			f.close
		);
		vi.runAllTimers();
		expect(f.close).not.toHaveBeenCalled();
		f.outside.focus();
		selectContentFocusout(
			{ relatedTarget: f.outside } as unknown as FocusEvent,
			f.content,
			f.trigger,
			f.close
		);
		vi.runAllTimers();
		expect(f.close).toHaveBeenCalledWith(false);
		expect(f.active()).toBe(f.outside);
	});
});

describe('Select component compilation', () => {
	it.each(['client', 'server'] as const)('compiles for %s without warnings', (generate) => {
		const filename = new URL('../components/common/Select.svelte', import.meta.url);
		const result = compile(readFileSync(filename, 'utf8'), {
			filename: filename.pathname,
			generate
		});
		expect(result.warnings).toEqual([]);
		expect(result.js.code.length).toBeGreaterThan(0);
	});
});
