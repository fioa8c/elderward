// Renders .wordpress-org/*.png from the HTML written by make-logo.py (Playwright + Chromium).
const { chromium } = require('playwright');
const path = require('path');
(async () => {
  const browser = await chromium.launch();
  const jobs = [
    ['banner-1544x500', 1544, 500, 1], ['banner-772x250', 772, 250, 1],
    ['icon-256x256', 256, 256, 1], ['icon-128x128', 128, 128, 1],
  ];
  for (const [name, w, h, dpr] of jobs) {
    const ctx = await browser.newContext({ viewport: { width: w, height: h }, deviceScaleFactor: dpr });
    const page = await ctx.newPage();
    await page.goto('file://' + path.resolve(__dirname, 'out', name + '.html'));
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({ path: path.resolve(__dirname, '..', '..', '.wordpress-org', name + '.png'), clip: { x: 0, y: 0, width: w, height: h }, omitBackground: false });
    await ctx.close();
  }
  await browser.close();
  console.log('rendered');
})().catch(e => { console.error(e); process.exit(1); });
