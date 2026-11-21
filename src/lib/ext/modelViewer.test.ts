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
const fakeModel = (found: number[], root = 1) => ({
	search: vi.fn((_t: string, ok: (ids: number[]) => void, _err?: unknown, _attrs?: string[]) =>
		ok(found)
	),
	getRootId: () => root
});
const fakeViewer = () => ({
	hide: vi.fn(),
	showAll: vi.fn(),
	clearSelection: vi.fn(),
	fitToView: vi.fn(),
	setThemingColor: vi.fn(),
	clearThemingColors: vi.fn(),
	setAggregateIsolation: vi.fn(),
	setAggregateSelection: vi.fn(),
	impl: { fitToView: vi.fn() }
});
const arch = fakeModel([7, 8], 1);
const plumbing = fakeModel([], 2);
const loaded = [
	{ versionId: 'arch', model: arch },
	{ versionId: 'plumb', model: plumbing }
];

describe('model viewer payloads', () => {
	it('keeps identifiers only and rejects incomplete refs', () => {
		const ref = parseModelViewerRef({
			serverId: 'forma',
			projectId: 'b.p',
			versionIds: ['urn:v?version=1', 'urn:p?version=2'],
			region: 'US',
			name: 'Tower',
			access_token: 'leak'
		});
		expect(ref).toEqual({
			serverId: 'forma',
			projectId: 'b.p',
			versionIds: ['urn:v?version=1', 'urn:p?version=2'],
			region: 'US',
			name: 'Tower'
		});
		expect(parseModelViewerRef({ serverId: 'forma', projectId: 'b.p' })).toBeNull();
		expect(parseModelViewerRef({ serverId: 'forma', projectId: 'b.p', versionIds: [] })).toBeNull();
		expect(
			parseModelViewerRef({ serverId: 'forma', projectId: 'b.p', versionIds: Array(6).fill('v') })
		).toBeNull();
		// Tabs saved before multi-model support
		expect(
			parseModelViewerRef({ serverId: 'forma', projectId: 'b.p', versionId: 'v1' })?.versionIds
		).toEqual(['v1']);
		expect(modelViewerTabId(ref!)).toBe('model-viewer:forma:urn:v?version=1|urn:p?version=2');
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
	const next = newCommands(get(modelViewerCommands), openedAt, ['v0', 'v1']);
	expect(next.commands.map((c) => c.action)).toEqual(['isolate', 'color']);
	expect(next.lastSeq).toBe(openedAt + 3);
	expect(newCommands(get(modelViewerCommands), next.lastSeq, ['v1']).commands).toEqual([]);
	for (let i = 0; i < 30; i++) sendModelViewerCommand({ action: 'fit' });
	expect(get(modelViewerCommands)).toHaveLength(20);
});

describe('applyModelViewerCommand', () => {
	it('isolates search matches across models and hides models without any', async () => {
		const viewer = fakeViewer();
		const command = { action: 'isolate', search: 'Doors', search_property: 'Category' } as const;
		expect(await applyModelViewerCommand(viewer, loaded, command, THREE)).toBe(2);
		expect(arch.search.mock.calls.at(-1)!.slice(0, 1)).toEqual(['Doors']);
		expect(plumbing.search.mock.calls.at(-1)![3]).toEqual(['Category']);
		expect(viewer.setAggregateIsolation).toHaveBeenCalledWith([{ model: arch, ids: [7, 8] }]);
		expect(viewer.fitToView).toHaveBeenCalledWith([7, 8], arch);
	});

	it('leaves the view unchanged when nothing matches', async () => {
		const viewer = fakeViewer();
		const command = { action: 'isolate', search: 'Doors', version_id: 'plumb' } as const;
		expect(await applyModelViewerCommand(viewer, loaded, command, THREE)).toBe(0);
		expect(viewer.setAggregateIsolation).not.toHaveBeenCalled();
	});

	it('db_ids go to the named model, else the first', async () => {
		const viewer = fakeViewer();
		await applyModelViewerCommand(viewer, loaded, { action: 'select', db_ids: [3] }, THREE);
		expect(viewer.setAggregateSelection).toHaveBeenCalledWith([{ model: arch, ids: [3] }]);
		await applyModelViewerCommand(
			viewer,
			loaded,
			{ action: 'color', db_ids: [3, 4], color: '#ff0000', version_id: 'plumb' },
			THREE
		);
		expect(viewer.setThemingColor.mock.calls.map((c) => [c[0], c[2]])).toEqual([
			[3, plumbing],
			[4, plumbing]
		]);
		expect(viewer.setThemingColor.mock.calls[0][1]).toEqual({ v: [1, 0, 0, 1] });
	});

	it('reset clears every model and fits them all', async () => {
		const viewer = fakeViewer();
		await applyModelViewerCommand(viewer, loaded, { action: 'reset_view' }, THREE);
		expect(viewer.showAll).toHaveBeenCalled();
		expect(viewer.clearThemingColors.mock.calls.map((c) => c[0])).toEqual([arch, plumbing]);
		expect(viewer.impl.fitToView).toHaveBeenCalledWith([
			{ model: arch, selection: [1] },
			{ model: plumbing, selection: [2] }
		]);
	});
});

it('ModelViewer.svelte compiles', () => {
	const source = readFileSync(new URL('./ModelViewer.svelte', import.meta.url), 'utf8');
	const { warnings } = compile(source, { filename: 'ModelViewer.svelte', generate: 'client' });
	expect(warnings).toEqual([]);
});
