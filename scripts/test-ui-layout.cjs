'use strict';

// Behavioural layout checks, shared by the Playwright suite and a manual fixture.
// These assertions inspect rendered geometry, not CSS spelling or screenshots.
function auditClientLayout() {
  const failures = [];
  const visible = el => el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden';
  if (document.documentElement.scrollWidth > innerWidth + 1) failures.push('page has horizontal overflow');
  for (const el of document.querySelectorAll('button, input, summary')) {
    if (!visible(el)) continue;
    const r = el.getBoundingClientRect();
    const name = el.id || el.textContent.trim().slice(0, 50);
    if (r.width < 44 || r.height < 44) failures.push('small hit target: ' + name);
    if (r.left < -1 || r.right > innerWidth + 1) failures.push('control outside viewport: ' + name);
    if (el.tagName !== 'INPUT' && el.scrollWidth > el.clientWidth + 1) failures.push('clipped control label: ' + name);
    if (el.tagName === 'INPUT' && parseFloat(getComputedStyle(el).fontSize) < 16) failures.push('small input text: ' + name);
  }
  for (const el of document.querySelectorAll('.row-copy, .hero-copy, .section-intro, .request-sources, .activity-item, dialog[open]')) {
    if (visible(el) && el.scrollWidth > el.clientWidth + 1) failures.push('clipped content: ' + (el.id || el.className));
  }
  for (const el of document.querySelectorAll('.small, .row-copy p, .hero p, .section-intro p, label, .primary, .secondary')) {
    if (visible(el) && parseFloat(getComputedStyle(el).fontSize) < 14) failures.push('small body text: ' + (el.id || el.className));
  }
  for (const el of document.querySelectorAll('dialog[open]')) {
    const r = el.getBoundingClientRect();
    if (r.top < -1 || r.bottom > innerHeight + 1) failures.push('dialog outside viewport');
    if (!el.getAttribute('aria-labelledby')) failures.push('unnamed dialog');
  }
  return failures;
}

const longTarget = 'long-subdomain-'.repeat(10) + 'example.net';
const longPath = '/Applications/' + 'Example Browser '.repeat(15) + '.app/Contents/MacOS/Browser';
function layoutFixture() {
  const app = {id:'layout-app', name:'Браузер с очень длинным названием приложения', path:longPath, target:longTarget, decision:'addresses', platform:'darwin'};
  return {
    account_id:'layout-account', device_id:'layout-device', status:'ready', tunnel:true, guard:true,
    rules:[longTarget, '2001:4860:4860::8888'], pending_protection:[longTarget], revision:1,
    requests:[], request_groups:[{target:longTarget, count:123456, sources:[app], requests:[{target:longTarget, count:123456, sources:[app]}]}],
    applications:[app], pending_applications:[], attribution_available:true,
    devices:[{id:'layout-device', name:'УстройствоБезПробелов'.repeat(12), platform:'darwin', expires:'2099-01-01', revoked:false}],
    events:[{id:1, kind:'outage', title:'Проверка длинного адреса', message:longTarget, at:'2026-01-01T12:00:00Z'}]
  };
}

async function testClientLayout(page, state) {
  const saved = structuredClone(state);
  Object.keys(state).forEach(key => delete state[key]);
  Object.assign(state, layoutFixture());
  const check = async context => {
    const errors = await page.evaluate(auditClientLayout);
    if (errors.length) throw Error(context + ': ' + errors.join('; '));
  };
  try {
    await page.evaluate(() => update());
    for (const width of [320, 360, 390, 640, 760, 1024, 1280, 1440, 1920]) {
      await page.setViewportSize({width, height:width < 640 ? 844 : 620});
      for (const theme of ['light', 'dark']) {
        if (await page.locator('html').getAttribute('data-theme') !== theme) await page.locator('#theme').click();
        for (const view of ['overview', 'requests', 'rules', 'applications', 'devices']) {
          await page.locator('[data-view="' + view + '"]').click();
          await check(width + '/' + theme + '/' + view);
          if ((width === 390 || width === 1440) && view === 'requests') {
            await page.screenshot({path:'build/ui-layout-' + width + '-' + theme + '.png', fullPage:true});
          }
        }
      }
    }

    // Text-only enlargement is stricter than simply making a screenshot bigger.
    await page.setViewportSize({width:390, height:844});
    await page.evaluate(() => document.documentElement.style.fontSize = '200%');
    for (const view of ['overview', 'requests', 'rules', 'applications', 'devices']) {
      await page.locator('[data-view="' + view + '"]').click();
      await check('200% text/' + view);
    }
    await page.evaluate(() => document.documentElement.style.fontSize = '');

    // Small landscape/keyboard viewport: dialog actions remain reachable by scroll.
    await page.setViewportSize({width:640, height:320});
    await page.locator('[data-view="rules"]').click();
    const remove = page.locator('#rules-list .danger').first();
    await remove.focus();
    await remove.press('Enter');
    await page.locator('#confirm').waitFor({state:'visible'});
    await check('short confirmation');
    await page.locator('#confirm [value="cancel"]').click();
    await remove.waitFor({state:'visible'});
    await page.waitForFunction(() => !document.querySelector('#rules-list .danger').disabled);
    if (!await remove.evaluate(el => el === document.activeElement)) throw Error('dialog did not return keyboard focus');

    state.pending_applications = [{...state.applications[0], id:'layout-prompt', decision:'pending'}];
    await page.evaluate(() => { nextApplicationPrompt=0; return update(); });
    await page.locator('#application-prompt').waitFor({state:'visible'});
    await check('short application dialog');
    await page.locator('#application-prompt [value="later"]').click();
    state.pending_applications=[];

    state.account_id='';
    await page.evaluate(() => update());
    for (const width of [320, 390, 760, 1440]) {
      await page.setViewportSize({width, height:620});
      for (const mode of ['login', 'register', 'pair']) {
        await page.locator('#tab-' + mode).click();
        await check('setup/' + width + '/' + mode);
      }
    }
    await page.emulateMedia({reducedMotion:'reduce'});
    if (await page.locator('button').first().evaluate(el => getComputedStyle(el).transitionDuration !== '0s')) throw Error('reduced motion ignored');
    console.log('Client layout: 90 view/theme/viewport combinations, 200% text, short dialogs and setup passed');
  } catch (error) {
    await page.screenshot({path:'build/ui-layout-failure.png', fullPage:true});
    throw error;
  } finally {
    await page.evaluate(() => { document.documentElement.style.fontSize=''; document.querySelectorAll('dialog[open]').forEach(d=>d.close('later')); });
    Object.keys(state).forEach(key => delete state[key]);
    Object.assign(state, saved);
    await page.emulateMedia({reducedMotion:'no-preference'});
    await page.evaluate(() => update());
  }
}

module.exports = {auditClientLayout, layoutFixture, testClientLayout};
