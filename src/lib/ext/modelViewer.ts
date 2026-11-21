import { writable } from 'svelte/store';
import { WEBUI_API_BASE_URL } from '$lib/constants';

/** What a Model viewer tab saves: identifiers only, never a token. */
export type ModelViewerRef = {
	serverId: string;
	projectId: string;
	/** One or more models shown overlaid, at most MAX_MODELS. */
	versionIds: string[];
	region?: string | null;
	name?: string;
};

export type ModelViewerCommand = {
	action:
		| 'isolate'
		| 'hide'
		| 'show_all'
		| 'select'
		| 'clear_selection'
		| 'fit'
		| 'color'
		| 'clear_colors'
		| 'reset_view';
	db_ids?: number[];
	search?: string;
	search_property?: string;
	color?: string;
	version_id?: string;
};

export type ViewerToken = {
	access_token: string;
	expires_in: number;
	models: { version_id: string; urn: string }[];
};
export type LoadedModel = { versionId: string; model: any };
type Target = { model: any; ids: number[] };

export const MAX_MODELS = 5;

// Pinned major: v8 drops APIs used below.
const VIEWER_BASE = 'https://developer.api.autodesk.com/modelderivative/v2/viewers/7.*';
const ACTIONS = new Set([
	'isolate',
	'hide',
	'show_all',
	'select',
	'clear_selection',
	'fit',
	'color',
	'clear_colors',
	'reset_view'
]);
const text = (value: unknown, max: number) =>
	typeof value === 'string' && value.length > 0 && value.length <= max;

export function parseModelViewerRef(data: unknown): ModelViewerRef | null {
	const d = data as Record<string, unknown> | null;
	const versionIds = Array.isArray(d?.versionIds) ? d.versionIds : [];
	if (
		!d ||
		!text(d.serverId, 256) ||
		!text(d.projectId, 256) ||
		!versionIds.length ||
		versionIds.length > MAX_MODELS ||
		!versionIds.every((id) => text(id, 2048))
	)
		return null;
	return {
		serverId: d.serverId as string,
		projectId: d.projectId as string,
		versionIds: versionIds as string[],
		region: text(d.region, 16) ? (d.region as string) : null,
		name: text(d.name, 200) ? (d.name as string) : 'Model'
	};
}

export function parseModelViewerCommand(data: unknown): ModelViewerCommand | null {
	const d = data as Record<string, unknown> | null;
	if (!d || !ACTIONS.has(d.action as string)) return null;
	const ids = Array.isArray(d.db_ids)
		? d.db_ids.filter((id): id is number => Number.isInteger(id) && id > 0).slice(0, 1000)
		: [];
	return {
		action: d.action as ModelViewerCommand['action'],
		db_ids: ids,
		search: text(d.search, 200) ? (d.search as string) : undefined,
		search_property: text(d.search_property, 200) ? (d.search_property as string) : undefined,
		color: typeof d.color === 'string' && /^#[0-9a-fA-F]{6}$/.test(d.color) ? d.color : undefined,
		version_id: text(d.version_id, 2048) ? (d.version_id as string) : undefined
	};
}

/** Recent AI commands in order; every open viewer tab applies the new ones addressed to it. */
export const modelViewerCommands = writable<{ seq: number; command: ModelViewerCommand }[]>([]);
let seq = 0;
// shortcut: keeps the last 20, so a tab still loading after 20 more commands misses the oldest; raise if that happens.
export const sendModelViewerCommand = (command: ModelViewerCommand) =>
	modelViewerCommands.update((list) => [...list, { seq: ++seq, command }].slice(-20));

/** Commands after `lastSeq` for this tab (untargeted, or naming one of its models), in order, and the new `lastSeq`. */
export function newCommands(
	list: { seq: number; command: ModelViewerCommand }[],
	lastSeq: number,
	versionIds: string[]
) {
	const fresh = list.filter((entry) => entry.seq > lastSeq);
	return {
		commands: fresh
			.map((entry) => entry.command)
			.filter((command) => !command.version_id || versionIds.includes(command.version_id)),
		lastSeq: fresh.at(-1)?.seq ?? lastSeq
	};
}

export const modelViewerTabId = (ref: ModelViewerRef) =>
	`model-viewer:${ref.serverId}:${ref.versionIds.join('|')}`;

export async function getViewerToken(
	token: string,
	ref: ModelViewerRef,
	signal?: AbortSignal
): Promise<ViewerToken> {
	const response = await fetch(`${WEBUI_API_BASE_URL}/ext/model-viewer/token`, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			authorization: `Bearer ${token}`
		},
		body: JSON.stringify({
			server_id: ref.serverId,
			project_id: ref.projectId,
			version_ids: ref.versionIds,
			...(ref.region ? { region: ref.region } : {})
		}),
		cache: 'no-store',
		signal
	});
	const body = await response.json().catch(() => ({}));
	if (!response.ok) throw new Error(body?.detail || 'Model viewer unavailable');
	latest = { token: body as ViewerToken, until: Date.now() + body.expires_in * 1000 };
	return body as ViewerToken;
}

let viewerRuntime: Promise<any> | null = null;
let tokenSource: (() => Promise<ViewerToken>) | null = null;
// The viewer asks for a token right after a tab just fetched one; reuse it instead of another Autodesk refresh.
let latest: { token: ViewerToken; until: number } | null = null;

/** Load Autodesk's viewer once; the token callback asks the most recently opened tab. */
export function loadViewerRuntime(source: () => Promise<ViewerToken>): Promise<any> {
	tokenSource = source;
	viewerRuntime ??= new Promise((resolve, reject) => {
		const css = document.createElement('link');
		css.rel = 'stylesheet';
		css.href = `${VIEWER_BASE}/style.min.css`;
		document.head.appendChild(css);
		const script = document.createElement('script');
		script.src = `${VIEWER_BASE}/viewer3D.min.js`;
		script.onerror = () => reject(new Error('Autodesk viewer failed to load'));
		script.onload = () => {
			const Viewing = (window as any).Autodesk.Viewing;
			// Automatic region routing (v7.109.1+), so no per-region api value.
			Viewing.FeatureFlags?.set?.('DS_ENDPOINTS', true);
			Viewing.Initializer(
				{
					env: 'AutodeskProduction2',
					api: 'streamingV2',
					getAccessToken: (done: (token: string, expires: number) => void) => {
						const left = (latest?.until ?? 0) - Date.now();
						if (latest && left > 60_000)
							return done(latest.token.access_token, Math.floor(left / 1000));
						tokenSource?.()
							.then((t) => done(t.access_token, t.expires_in))
							.catch((error) => console.error('Model viewer token', error));
					}
				},
				() => resolve(Viewing)
			);
		};
		document.head.appendChild(script);
	});
	viewerRuntime.catch(() => (viewerRuntime = null));
	return viewerRuntime;
}

const hexToVector = (THREE: any, hex: string) =>
	new THREE.Vector4(
		parseInt(hex.slice(1, 3), 16) / 255,
		parseInt(hex.slice(3, 5), 16) / 255,
		parseInt(hex.slice(5, 7), 16) / 255,
		1
	);

const searchModel = (model: any, command: ModelViewerCommand): Promise<number[]> =>
	new Promise((resolve) =>
		model.search(
			command.search,
			(ids: number[]) => resolve(ids),
			() => resolve([]),
			command.search_property ? [command.search_property] : undefined
		)
	);

/** version_id scopes a command to one model; search covers every scoped model, db_ids the first. */
async function resolveTargets(
	models: LoadedModel[],
	command: ModelViewerCommand
): Promise<Target[]> {
	const scoped = command.version_id
		? models.filter((m) => m.versionId === command.version_id)
		: models;
	if (command.search) {
		const found = await Promise.all(
			scoped.map(async (m) => ({ model: m.model, ids: await searchModel(m.model, command) }))
		);
		return found.filter((target) => target.ids.length);
	}
	return command.db_ids?.length && scoped[0]
		? [{ model: scoped[0].model, ids: command.db_ids }]
		: [];
}

function fit(viewer: any, targets: Target[]) {
	if (targets.length === 1) return viewer.fitToView(targets[0].ids, targets[0].model);
	// shortcut: v7 has no public multi-model fit; uses the internal aggregate fitToView, else fits the first model.
	if (viewer.impl?.fitToView)
		return viewer.impl.fitToView(targets.map((t) => ({ model: t.model, selection: t.ids })));
	viewer.fitToView(targets[0]?.ids, targets[0]?.model);
}

/** Apply one AI command to the tab's loaded models; returns how many objects it targeted. */
export async function applyModelViewerCommand(
	viewer: any,
	models: LoadedModel[],
	command: ModelViewerCommand,
	THREE: any = (window as any).THREE
): Promise<number> {
	const targets = await resolveTargets(models, command);
	const count = targets.reduce((sum, target) => sum + target.ids.length, 0);
	// No match: leave the view as it is rather than isolating nothing (which shows everything).
	if (['isolate', 'hide', 'select', 'color'].includes(command.action) && !count) return 0;
	const everything = models.map((m) => ({ model: m.model, ids: [m.model.getRootId()] }));
	switch (command.action) {
		case 'isolate':
			viewer.setAggregateIsolation(targets); // hides models without matches
			fit(viewer, targets);
			break;
		case 'hide':
			for (const t of targets) viewer.hide(t.ids, t.model);
			break;
		case 'show_all':
			viewer.showAll();
			break;
		case 'select':
			viewer.clearSelection();
			viewer.setAggregateSelection(targets);
			break;
		case 'clear_selection':
			viewer.clearSelection();
			break;
		case 'fit':
			fit(viewer, targets.length ? targets : everything);
			break;
		case 'color': {
			const color = hexToVector(THREE, command.color ?? '#ff0000');
			for (const t of targets)
				for (const id of t.ids) viewer.setThemingColor(id, color, t.model, true);
			break;
		}
		case 'clear_colors':
			for (const m of models) viewer.clearThemingColors(m.model);
			break;
		case 'reset_view':
			viewer.clearSelection();
			for (const m of models) viewer.clearThemingColors(m.model);
			viewer.showAll();
			fit(viewer, everything);
			break;
	}
	return count;
}
