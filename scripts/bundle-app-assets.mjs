#!/usr/bin/env node
/**
 * Copies the Astro build output (dist/) into the Android project's assets and
 * rewrites root-absolute URLs (href="/blog") into file:///android_asset/www/...
 * URLs so the site can be served from inside the APK with no web server.
 *
 * Usage: node scripts/bundle-app-assets.mjs [--dist dist] [--out android/app/src/main/assets/www]
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const args = process.argv.slice(2);
function argValue(flag, fallback) {
	const i = args.indexOf(flag);
	return i === -1 ? fallback : args[i + 1];
}

const dist = path.resolve(argValue('--dist', 'dist'));
const out = path.resolve(argValue('--out', 'android/app/src/main/assets/www'));
const BASE = 'file:///android_asset/www';

// Files that must not ship inside the APK. `_worker.js`, `.assetsignore` and
// `_routes.json` are Cloudflare deployment plumbing; the sitemap entries keep
// the bundle lean. `sw.js` stays: it is inert under file:// but harmless.
const SKIP_DIRS = new Set(['_worker.js']);
const SKIP_FILES = new Set(['.assetsignore', '_routes.json', 'sitemap-index.xml', 'sitemap-0.xml']);

async function walk(dir, base = dir) {
	const entries = [];
	for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) {
			if (SKIP_DIRS.has(path.relative(base, full).split(path.sep)[0])) continue;
			entries.push(...(await walk(full, base)));
		} else if (!SKIP_FILES.has(entry.name)) {
			entries.push(full);
		}
	}
	return entries;
}

/** Every file that exists in dist, keyed by its site-relative URL path. */
async function inventory() {
	const files = await walk(dist);
	return new Set(files.map((f) => '/' + path.relative(dist, f).split(path.sep).join('/')));
}

const known = await inventory();

/** "/blog/first-post/" -> "/blog/first-post/index.html" when that file exists. */
function resolveToFile(urlPath) {
	const [raw, hash = ''] = urlPath.split('#');
	if (!raw || raw.endsWith('/')) {
		const index = `${raw}index.html`;
		return known.has(index) ? index + (hash ? `#${hash}` : '') : urlPath;
	}
	if (!path.extname(raw)) {
		const withSlash = `${raw}/index.html`;
		if (known.has(withSlash)) return withSlash + (hash ? `#${hash}` : '');
		const direct = `${raw}.html`;
		if (known.has(direct)) return direct + (hash ? `#${hash}` : '');
	}
	return urlPath;
}

const stats = { files: 0, html: 0, css: 0, rewrites: 0, unresolved: [] };

function toAssetUrl(urlPath) {
	const resolved = resolveToFile(urlPath);
	if (!known.has(resolved.split('#')[0])) stats.unresolved.push(urlPath);
	stats.rewrites++;
	return BASE + resolved;
}

const isLocal = (value) =>
	typeof value === 'string' && value.startsWith('/') && !value.startsWith('//');

function rewriteAttributes(html) {
	return html.replace(
		/\s(href|src|content|poster|data-src|data-href)="(\/[^"]*)"/g,
		(match, attr, value) => {
			if (!isLocal(value)) return match;
			// Leave OpenGraph/canonical absolute URLs and protocol-relative URLs alone.
			return ` ${attr}="${toAssetUrl(value)}"`;
		},
	);
}

function rewriteSrcset(html) {
	return html.replace(/\ssrcset="([^"]*)"/g, (match, value) => {
		const parts = value.split(',').map((part) => {
			const [url, ...rest] = part.trim().split(/\s+/);
			if (!isLocal(url)) return part.trim();
			return [toAssetUrl(url), ...rest].join(' ');
		});
		return ` srcset="${parts.join(', ')}"`;
	});
}

function rewriteCss(css) {
	return css.replace(/url\(\s*(['"]?)(\/[^)'"]*)\1\s*\)/g, (match, quote, value) => {
		if (value.startsWith('//')) return match;
		return `url("${toAssetUrl(value)}")`;
	});
}

/** Astro inlines scoped <style> blocks, so they need the CSS treatment too. */
function rewriteStyleBlocks(html) {
	return html.replace(/<style([^>]*)>([\s\S]*?)<\/style>/g, (match, attrs, css) =>
		`<style${attrs}>${rewriteCss(css)}</style>`,
	);
}

await fs.rm(out, { recursive: true, force: true });

for (const file of await walk(dist)) {
	const rel = path.relative(dist, file);
	const target = path.join(out, rel);
	await fs.mkdir(path.dirname(target), { recursive: true });
	const ext = path.extname(file).toLowerCase();
	stats.files++;

	if (ext === '.html') {
		const source = await fs.readFile(file, 'utf8');
		await fs.writeFile(
			target,
			rewriteStyleBlocks(rewriteSrcset(rewriteAttributes(source))),
		);
		stats.html++;
	} else if (ext === '.css') {
		const source = await fs.readFile(file, 'utf8');
		await fs.writeFile(target, rewriteCss(source));
		stats.css++;
	} else if (ext === '.js') {
		// sw.js is the PWA worker for the live site; its root-absolute cache keys
		// are correct there and it never runs under file://, so don't scan it.
		if (rel !== 'sw.js') {
			const source = await fs.readFile(file, 'utf8');
			const hits = source.match(/["'(]\/(?!\/)[A-Za-z0-9_@./-]+/g);
			for (const hit of hits ?? []) stats.unresolved.push(`${rel}: ${hit}`);
		}
		await fs.copyFile(file, target);
	} else {
		await fs.copyFile(file, target);
	}
}

console.log(`bundled ${stats.files} files (${stats.html} html, ${stats.css} css) -> ${path.relative(process.cwd(), out)}`);
console.log(`rewrote ${stats.rewrites} root-absolute URLs`);
if (stats.unresolved.length) {
	console.warn(`\nWARNING: ${stats.unresolved.length} reference(s) did not resolve to a bundled file:`);
	for (const u of stats.unresolved) console.warn(`  - ${u}`);
}
