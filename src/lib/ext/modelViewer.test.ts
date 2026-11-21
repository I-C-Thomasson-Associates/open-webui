import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { get } from 'svelte/store';
import { compile } from 'svelte/compiler';
import {
	applyModelViewerCommand,
	modelViewerCommands,
	modelViewerTabId,
	newCommands,
	sendModelViewerCommand,
	parseModelViewerCommand,
	parseModelViewerRef
} from './modelViewer';

const THREE = {
	Vector4: class {
		constructor(...v: number[]) {
			Object.assign(this, { v });
		}
	}
};
const fakeViewer = (found: number[] = [7, 8]) => ({
	isolate: vi.fn(),
	hide: vi.fn(),
	showAll: vi.fn(),
	select: vi.fn(),
	clearSelection: vi.fn(),
	fitToView: vi.fn(),
	setThemingColor: vi.fn(),
	clearThemingColors: vi.fn(),
	search: vi.fn((_t: string, ok: (ids: number[]) => void) => ok(found))
});

describe('model viewer payloads', () => {
	it('keeps identifiers only and rejects incomplete refs', () => {
		const ref = parseModelViewerRef({
			serverId: 'forma',
			projectId: 'b.p',
			versionId: 'urn:v?version=1',
			region: 'US',
			name: 'Tower',
			access_token: 'leak'
		});
		expect(ref).toEqual({
			serverId: 'forma',
			projectId: 'b.p',
			versionId: 'urn:v?version=1',
			region: 'US',
			name: 'Tower'
		});
		expect(parseModelViewerRef({ serverId: 'forma', projectId: 'b.p' })).toBeNull();
		expect(modelViewerTabId(ref!)).toBe('model-viewer:forma:urn:v?version=1');
	});

	it('validates commands', () => {
		expect(parseModelViewerCommand({ action: 'explode' })).toBeNull();
		expect(
			parseModelViewerCommand({ action: 'color', db_ids: [1, -2, 1.5, 'x'], color: 'red' })
		).toEqual({
			action: 'color',
			db_ids: [1],
			search: undefined,
			search_property: undefined,
			color: undefined,
			version_id: undefined
		});
	});
});

it('a loading tab still gets commands sent after it opened, in order, for its version', () => {
	sendModelViewerCommand({ action: 'fit' });
	const openedAt = get(modelViewerCommands).at(-1)!.seq;
	sendModelViewerCommand({ action: 'isolate', search: 'Doors' });
	sendModelViewerCommand({ action: 'hide', db_ids: [1], version_id: 'other' });
	sendModelViewerCommand({ action: 'color', db_ids: [2], color: '#00ff00', version_id: 'v1' });
	const next = newCommands(get(modelViewerCommands), openedAt, 'v1');
	expect(next.commands.map((c) => c.action)).toEqual(['isolate', 'color']);
	expect(next.lastSeq).toBe(openedAt + 3);
	expect(newCommands(get(modelViewerCommands), next.lastSeq, 'v1').commands).toEqual([]);
	for (let i = 0; i < 30; i++) sendModelViewerCommand({ action: 'fit' });
	expect(get(modelViewerCommands)).toHaveLength(20);
});

describe('applyModelViewerCommand', () => {
	it('isolates search results limited to a property', async () => {
		const viewer = fakeViewer();
		const count = await applyModelViewerCommand(
			viewer,
			{ action: 'isolate', search: 'Doors', search_property: 'Category' },
			THREE
		);
		expect(count).toBe(2);
		expect(viewer.search.mock.calls[0][0]).toBe('Doors');
		expect(viewer.search.mock.calls[0][3]).toEqual(['Category']);
		expect(viewer.isolate).toHaveBeenCalledWith([7, 8]);
	});

	it('leaves the view unchanged when nothing matches', async () => {
		const viewer = fakeViewer([]);
		expect(
			await applyModelViewerCommand(viewer, { action: 'isolate', search: 'None' }, THREE)
		).toBe(0);
		expect(viewer.isolate).not.toHaveBeenCalled();
	});

	it('colors ids and resets', async () => {
		const viewer = fakeViewer();
		await applyModelViewerCommand(
			viewer,
			{ action: 'color', db_ids: [3, 4], color: '#ff0000' },
			THREE
		);
		expect(viewer.setThemingColor).toHaveBeenCalledTimes(2);
		expect(viewer.setThemingColor.mock.calls[0][1]).toEqual({ v: [1, 0, 0, 1] });
		await applyModelViewerCommand(viewer, { action: 'reset_view' }, THREE);
		expect(viewer.showAll).toHaveBeenCalled();
		expect(viewer.clearThemingColors).toHaveBeenCalled();
	});
});

it('ModelViewer.svelte compiles', () => {
	const source = readFileSync(new URL('./ModelViewer.svelte', import.meta.url), 'utf8');
	const { warnings } = compile(source, { filename: 'ModelViewer.svelte', generate: 'client' });
	expect(warnings).toEqual([]);
});
