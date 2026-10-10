import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const source = readFileSync(new URL('./Models.svelte', import.meta.url), 'utf-8');
const init = source.slice(source.indexOf('const init = async'), source.indexOf('const saveModelOrder'));

describe('admin Models init', () => {
	it('has no unresolved merge markers', () => {
		expect(source).not.toMatch(/^(<<<<<<<|=======|>>>>>>>)/m);
	});

	it('does not append unavailable saved rows but tracks availability', () => {
		expect(init).toContain('availableModelIds = new Set(allModels.map');
		expect(init).not.toMatch(/allModels\.push\(\s*\.\.\.savedModels/);
	});

	it('keeps tag extraction, selectedTag reset and filtering', () => {
		expect(init).toContain('tags = [...new Set(mergedModels.flatMap(modelTags))].sort()');
		expect(init).toContain("selectedTag = ''");
		expect(init).toContain('mergedModels.filter((model) => !selectedTag || modelTags(model).includes(selectedTag))');
	});
});
