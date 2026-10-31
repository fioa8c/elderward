/*
 * End-to-end check of the admin page with Playwright.
 *
 *   ELDERWARD_URL=http://127.0.0.1:8089 ELDERWARD_USER=admin ELDERWARD_PASS=adminpass \
 *   ELDERWARD_LOG=/path/to/logs node tests/admin-ui.js
 *
 * Logs in, starts a scan from Tools > Elderward, waits for it to finish,
 * prints the severity counts from the findings table, downloads the JSON
 * export and checks it against the table, and verifies that the ajax
 * endpoints refuse requests without a nonce.
 */
const { chromium } = require('playwright');

const base = process.env.ELDERWARD_URL || 'http://127.0.0.1:8089';
const user = process.env.ELDERWARD_USER || 'admin';
const pass = process.env.ELDERWARD_PASS || 'adminpass';
const logPath = process.env.ELDERWARD_LOG || '';

(async () => {
	const browser = await chromium.launch();
	const page = await browser.newPage();
	const errors = [];
	page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
	page.on('console', (m) => { if (m.type() === 'error' && /elderward/.test(m.text())) { errors.push('console: ' + m.text()); } });

	await page.goto(base + '/wp-login.php');
	await page.fill('#user_login', user);
	await page.fill('#user_pass', pass);
	await page.click('#wp-submit');
	await page.waitForURL(/wp-admin/);

	await page.goto(base + '/wp-admin/tools.php?page=elderward');
	await page.waitForSelector('#elderward-start');
	if (logPath) {
		await page.fill('#elderward-log', logPath);
	}
	await page.click('#elderward-start');
	await page.waitForSelector('#elderward-progress:not([hidden])');

	// The page reloads itself when the job completes.
	await page.waitForFunction(() => {
		const el = document.getElementById('elderward-status-text');
		return el && /complete|failed|cancelled/i.test(el.textContent);
	}, null, { timeout: 600000 });
	await page.waitForLoadState('load');
	await page.waitForTimeout(1500);
	await page.goto(base + '/wp-admin/tools.php?page=elderward');

	const status = await page.textContent('.elderward-last');
	console.log('status line:', status.trim().replace(/\s+/g, ' '));

	const counts = await page.$$eval('.elderward-filters li', (items) => items.map((li) => li.textContent.trim().replace(/\s+/g, ' ')));
	console.log('filters:', counts.join(' '));

	const rows = await page.$$eval('.elderward-table tbody tr', (trs) => trs.map((tr) => {
		const tds = tr.querySelectorAll('td');
		return tds.length === 4 ? [tds[0].textContent.trim(), tds[1].textContent.trim(), tds[2].textContent.trim()] : null;
	}).filter(Boolean));
	console.log('table rows (first page):', rows.length);
	rows.slice(0, 40).forEach((r) => console.log('  ', r.join(' | ')));

	// JSON export must list the same (severity,type) multiset as the table.
	const [download] = await Promise.all([
		page.waitForEvent('download'),
		page.click('a.button[href*="format=json"]'),
	]);
	const path = await download.path();
	const lines = require('fs').readFileSync(path, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
	console.log('json export findings:', lines.length);
	const key = (s, t) => s + ',' + t;
	const tableSet = rows.map((r) => key(r[0], r[1])).sort().join('\n');
	const exportSet = lines.map((e) => key(e.severity, e.type)).sort().join('\n');
	console.log('export matches table:', tableSet === exportSet ? 'yes' : 'NO');

	// Security: no nonce, no service.
	const noNonce = await page.evaluate(async (ajaxUrl) => {
		const body = new FormData();
		body.append('action', 'elderward_step');
		const r = await fetch(ajaxUrl, { method: 'POST', credentials: 'same-origin', body });
		return r.status;
	}, base + '/wp-admin/admin-ajax.php');
	console.log('ajax without nonce -> HTTP', noNonce);

	const anonContext = await browser.newContext();
	const logged = await anonContext.newPage();
	const anon = await logged.goto(base + '/wp-admin/admin-post.php?action=elderward_export&format=json');
	const anonBody = await anon.text();
	const anonOk = !/"event":"finding"/.test(anonBody);
	console.log('anonymous export -> HTTP', anon.status(), 'leaked findings:', anonOk ? 'no' : 'YES');
	await anonContext.close();

	console.log('browser errors:', errors.length ? errors : 'none');
	await browser.close();
	process.exit(tableSet === exportSet && noNonce === 403 && anonOk && !errors.length ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(1); });
