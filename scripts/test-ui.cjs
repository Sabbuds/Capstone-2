const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const javaBin = process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin') : '';
const executable = name => path.join(javaBin, name + (process.platform === 'win32' ? '.exe' : ''));
const artifacts = path.join(root, '.benchmark-cache', 'ui-tests');
const servers = [];
let checks = 0;

async function startServer(profile) {
  const reservation = net.createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const args = profile ? ['-Dcapstone.target.commandProfile=' + profile] : [];
  const child = spawn(executable('java'), [...args, '-cp', 'out',
    'edu.fiu.capstone.ui.UiServer', '--port', String(port)], { cwd: root, windowsHide: true });
  servers.push(child);
  await new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('UI server startup timed out\n' + output)), 15000);
    child.once('error', reject);
    child.once('exit', code => reject(new Error('UI server exited ' + code + '\n' + output)));
    child.stderr.on('data', data => { output += data; });
    child.stdout.on('data', data => {
      output += data;
      if (output.includes('UI running at')) { clearTimeout(timer); resolve(); }
    });
    child.once('exit', () => clearTimeout(timer));
  });
  return 'http://localhost:' + port;
}

async function check(name, action) {
  await action();
  checks++;
  console.log('PASS browser | ' + name);
}

async function idle(page) {
  await page.waitForFunction(() => !document.querySelector('#scan').disabled
    && document.querySelector('#code'), null, { timeout: 30000 });
}

async function scan(page, target, findings, proposals) {
  await page.selectOption('#target', target);
  const pending = page.waitForResponse(r => new URL(r.url()).pathname === '/api/scan');
  await page.click('#scan');
  const response = await pending;
  const report = await response.json();
  assert.equal(response.status(), 200, JSON.stringify(report));
  await idle(page);
  assert.equal(report.findings.length, findings, target);
  assert.equal(report.findings.filter(f => f.status === 'fixed').length, proposals, target);
  assert.equal(await page.locator('details.finding').count(), findings);
  return report;
}

async function upload(page, name, source) {
  const pending = page.waitForResponse(r => r.request().method() === 'POST'
    && new URL(r.url()).pathname === '/api/scan');
  await page.locator('#files').setInputFiles({ name, mimeType: 'text/plain', buffer: Buffer.from(source) });
  const response = await pending;
  const report = await response.json();
  await idle(page);
  return { response, report };
}

async function download(page, label) {
  const pending = page.waitForEvent('download');
  await page.getByRole('button', { name: label, exact: true }).click();
  const result = await pending;
  const destination = path.join(artifacts, result.suggestedFilename());
  await result.saveAs(destination);
  return { name: result.suggestedFilename(), text: await fs.readFile(destination, 'utf8') };
}

async function main() {
  process.chdir(root);
  await fs.mkdir(artifacts, { recursive: true });
  // Windows runners can expose TEMP through an 8.3 alias while Java returns the full path.
  const temporary = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'capstone-ui-')));
  const errors = [];
  let browser, page;
  const original = await fs.readFile('samples/demo/CustomerLookup.java', 'utf8');
  try {
    browser = await chromium.launch(process.env.BROWSER_EXECUTABLE
      ? { executablePath: process.env.BROWSER_EXECUTABLE }
      : { channel: 'msedge' });
    page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    page.on('pageerror', e => errors.push(e.message));
    const base = await startServer();
    await page.goto(base);
    await idle(page);
    await check('initial scan and accurate proposal labels', async () => {
      assert.match(await page.locator('#profile-badge').innerText(), /off/);
      assert.equal(await page.locator('details.finding').count(), 5);
      assert.match(await page.locator('body').innerText(), /Repair proposals/);
      assert.doesNotMatch(await page.locator('body').innerText(), /Fixed automatically/);
    });
    await check('built-in regression suites run from the UI and preserve scan results', async () => {
      assert.equal((await page.request.get(base + '/api/regression')).status(), 405);
      assert.equal((await page.request.post(base + '/api/regression', {
        headers: { Origin: 'https://example.invalid' }
      })).status(), 403);
      const pending = page.waitForResponse(r => new URL(r.url()).pathname === '/api/regression', { timeout: 150000 });
      await page.getByRole('button', { name: 'Run regression tests' }).click();
      const response = await pending;
      const result = await response.json();
      assert.equal(response.status(), 200, JSON.stringify(result));
      assert.equal(result.status, 'passed', result.output);
      await page.waitForFunction(() => document.querySelector('#regression-status').textContent.includes('passed'));
      await page.getByText('Test output', { exact: true }).click();
      assert.match(await page.locator('#regression-output').innerText(), /All Java regression suites passed/);
      assert.equal(await page.locator('details.finding').count(), 5);
    });
    await check('SQL repair preview and source navigation', async () => {
      await scan(page, 'samples/demo/CustomerLookup.java', 3, 2);
      await page.getByRole('button', { name: 'Expand all', exact: true }).click();
      await page.getByText('Show proposed change', { exact: true }).first().click();
      assert.ok(await page.locator('details.change[open] .diff .add').count() > 0);
      await page.getByRole('button', { name: 'With proposals (2)', exact: true }).click();
      assert.match(await page.locator('#code').innerText(), /prepareStatement/);
      await page.getByRole('button', { name: 'Original', exact: true }).click();
      await page.locator('details.finding button.loc').first().click();
      assert.ok(await page.locator('#code .flash').count() > 0);
    });
    await check('downloaded SQL proposals compile and remove the repaired findings', async () => {
      const result = await download(page, 'Download proposed file');
      assert.equal(result.name, 'CustomerLookup.java');
      assert.match(result.text, /prepareStatement/);
      await fs.writeFile(path.join(temporary, result.name), result.text);
      execFileSync(executable('javac'), ['--release', '17', '-d', temporary, path.join(temporary, result.name)]);
      const { response, report } = await upload(page, result.name, result.text);
      assert.equal(response.status(), 200);
      assert.equal(report.findings.length, 1);
      assert.equal(report.findings[0].status, 'manual');
    });
    await check('downloads preserve CRLF, Unicode and source filenames', async () => {
      const source = original.replace(/\r?\n/g, '\r\n').replace('Demo:', 'Demo café 😀:');
      await upload(page, 'CustomerLookup.java', source);
      const result = await download(page, 'Download proposed file');
      assert.match(result.text, /café 😀/);
      assert.ok(result.text.includes('\r\n'));
      assert.ok(!/(?<!\r)\n/.test(result.text));
    });
    await check('JSON and HTML exports describe proposals', async () => {
      const json = JSON.parse((await download(page, 'Export JSON')).text);
      assert.equal(json.summary.repairProposals, 2);
      assert.equal(json.findings.filter(f => f.status === 'proposed').length, 2);
      assert.deepEqual(json.classpath, []);
      const html = (await download(page, 'Export HTML report')).text;
      assert.match(html, /Repair proposals/);
      assert.doesNotMatch(html, /Fixed automatically/);
    });
    await check('multiple SQL proposals in one method have distinct variable names', async () => {
      const source = `import java.sql.*;
public class Multiple {
  void run(Connection conn, String a, String b) throws Exception {
    Statement stmt = conn.createStatement();
    int __ps_1 = 1;
    ResultSet first = stmt.executeQuery("SELECT * FROM users WHERE name = '" + a + "'");

    System.out.println(__ps_1);

    ResultSet second = stmt.executeQuery("SELECT * FROM users WHERE name = '" + b + "'");
  }
}`;
      const { report } = await upload(page, 'Multiple.java', source);
      assert.equal(report.findings.filter(f => f.status === 'fixed').length, 2);
      const result = await download(page, 'Download proposed file');
      await fs.writeFile(path.join(temporary, result.name), result.text);
      execFileSync(executable('javac'), ['--release', '17', '-d', temporary, path.join(temporary, result.name)]);
      assert.equal((await upload(page, result.name, result.text)).report.findings.length, 0);
    });
    await check('safe sample and default command repair refusals', async () => {
      await scan(page, 'samples/demo/FileViewer.java', 2, 0);
      await scan(page, 'samples/demo/SafeReports.java', 0, 0);
      assert.equal(await page.getByRole('button', { name: 'Download proposed file' }).count(), 0);
    });
    await check('accuracy chart and incomplete-analysis warning', async () => {
      const report = await scan(page, 'samples/sqli/', 22, 0);
      assert.equal(report.complete, false);
      assert.match(await page.locator('#notices').innerText(), /Analysis incomplete/);
      await page.locator('[data-fk="bar:tp"]').click();
      assert.ok(await page.locator('.cases li').count() > 0);
      await scan(page, 'samples/command/', 6, 0);
    });
    await check('uploaded file and invalid Java error recovery', async () => {
      const source = 'class Uploaded { void run(String s) throws Exception { new ProcessBuilder("sh","-c",s).start(); } }';
      assert.equal((await upload(page, 'Uploaded.java', source)).report.findings.length, 1);
      const invalid = await upload(page, 'Broken.java', 'class Broken { void bad( {');
      assert.equal(invalid.response.status(), 400);
      assert.match(await page.locator('#notices').innerText(), /parse/i);
      await scan(page, 'samples/demo/SafeReports.java', 0, 0);
    });
    await check('resource-only uploads explain the Java source requirement', async () => {
      await page.locator('#files').setInputFiles({ name: 'app.properties', mimeType: 'text/plain', buffer: Buffer.from('key=value') });
      assert.match(await page.locator('#notices').innerText(), /No .java files/);
      await scan(page, 'samples/demo/SafeReports.java', 0, 0);
    });
    await check('encoded upload limit gives a recoverable size error', async () => {
      const large = Buffer.alloc(6 * 1024 * 1024, ' ');
      await page.locator('#files').setInputFiles({ name: 'Large.java', mimeType: 'text/plain', buffer: large });
      await page.waitForFunction(() => !document.querySelector('#scan').disabled
        && document.querySelector('#notices').textContent.includes('encoded upload exceeds'));
      await scan(page, 'samples/demo/SafeReports.java', 0, 0);
    });

    const dependencySource = path.join(temporary, 'Helper.java');
    const classes = path.join(temporary, 'library classes');
    const jar = path.join(temporary, 'dependency library.jar');
    await fs.mkdir(classes);
    await fs.writeFile(dependencySource, 'package dependency; public class Helper { public static int number(){return 1;} }');
    execFileSync(executable('javac'), ['--release', '17', '-d', classes, dependencySource]);
    execFileSync(executable('jar'), ['--create', '--file', jar, '-C', classes, '.']);
    const dependent = 'class Dependent {void find(java.sql.Statement s)throws Exception {s.executeQuery("SELECT "+dependency.Helper.number());}}';
    await page.locator('.dependencies summary').click();
    await check('dependency directory resolves uploaded source', async () => {
      assert.equal((await upload(page, 'Dependent.java', dependent)).report.complete, false);
      await page.locator('#classpath').fill(classes);
      const { report } = await upload(page, 'Dependent.java', dependent);
      assert.equal(report.complete, true);
      assert.equal(report.findings.length, 0);
      assert.deepEqual(report.classpath, [classes]);
    });
    await check('dependency JAR, duplicate paths and report metadata', async () => {
      await page.locator('#classpath').fill(jar + '\n' + jar);
      const { report } = await upload(page, 'Dependent.java', dependent);
      assert.equal(report.complete, true);
      assert.deepEqual(report.classpath, [jar]);
      const exported = JSON.parse((await download(page, 'Export JSON')).text);
      assert.deepEqual(exported.classpath, [jar]);
      await scan(page, 'samples/demo/SafeReports.java', 0, 0);
    });
    await check('invalid dependency reports an actionable error', async () => {
      await page.locator('#classpath').fill(path.join(temporary, 'missing.jar'));
      const { response } = await upload(page, 'Dependent.java', dependent);
      assert.equal(response.status(), 400);
      assert.match(await page.locator('#notices').innerText(), /readable JAR or class directory/);
      await page.locator('#classpath').fill('');
      await scan(page, 'samples/demo/CustomerLookup.java', 3, 2);
    });
    await check('theme selection and mobile layout', async () => {
      await page.screenshot({ path: path.join(artifacts, 'desktop.png'), fullPage: true });
      const before = await page.locator('#theme').innerText();
      await page.locator('#theme').click();
      assert.notEqual(await page.locator('#theme').innerText(), before);
      await page.setViewportSize({ width: 390, height: 844 });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({ path: path.join(artifacts, 'mobile.png'), fullPage: true });
      await page.setViewportSize({ width: 1440, height: 1000 });
    });
    await check('invalid target, duplicate upload names and foreign origin rejected', async () => {
      assert.equal((await page.request.get(base + '/api/scan?target=../outside.java')).status(), 400);
      const entry = 'Same.java\t' + Buffer.from('class Same {}').toString('base64');
      const duplicate = await page.request.post(base + '/api/scan', { data: entry + '\n' + entry });
      assert.equal(duplicate.status(), 400);
      assert.match((await duplicate.json()).error, /Duplicate source/);
      assert.equal((await page.request.post(base + '/api/scan', {
        headers: { Origin: 'https://example.com' }, data: entry })).status(), 403);
    });

    await page.goto(await startServer('linux-gnu-cat'));
    await idle(page);
    await check('supported command repair download compiles and rescans', async () => {
      assert.match(await page.locator('#profile-badge').innerText(), /on.*linux-gnu-cat/);
      await scan(page, 'samples/demo/FileViewer.java', 2, 1);
      await page.getByRole('button', { name: 'With proposals (1)', exact: true }).click();
      const result = await download(page, 'Download proposed file');
      assert.equal(result.name, 'FileViewer.java');
      assert.match(result.text, /"--"/);
      await fs.writeFile(path.join(temporary, result.name), result.text);
      execFileSync(executable('javac'), ['--release', '17', '-d', temporary, path.join(temporary, result.name)]);
      assert.equal((await upload(page, result.name, result.text)).report.findings.length, 1);
    });
    await check('folder upload, combined counts and file tabs', async () => {
      const pending = page.waitForResponse(r => r.request().method() === 'POST');
      await page.locator('#folder').setInputFiles(path.join(root, 'samples', 'demo'));
      const report = await (await pending).json();
      await idle(page);
      assert.equal(report.files.length, 3);
      assert.equal(report.findings.length, 5);
      assert.equal(report.findings.filter(f => f.status === 'fixed').length, 3);
      await page.locator('.tabs .tab').filter({ hasText: 'SafeReports.java' }).click();
      assert.match(await page.locator('#code').innerText(), /class SafeReports/);
    });
    await check('source files preserved and no JavaScript exceptions', async () => {
      assert.equal(await fs.readFile('samples/demo/CustomerLookup.java', 'utf8'), original);
      assert.deepEqual(errors, []);
    });
    console.log(`Browser tests completed: ${checks}/${checks} passed.`);
  } catch (error) {
    if (page) await page.screenshot({ path: path.join(artifacts, 'failure.png'), fullPage: true }).catch(() => {});
    throw error;
  } finally {
    if (browser) await browser.close();
    await Promise.all(servers.map(async server => {
      if (server.exitCode !== null || server.signalCode !== null) return;
      const exited = once(server, 'exit');
      server.kill();
      await exited;
    }));
    // Only this test's newly created temporary directory is removed.
    assert.equal(path.dirname(temporary), await fs.realpath(os.tmpdir()));
    assert.ok(path.basename(temporary).startsWith('capstone-ui-'));
    await fs.rm(temporary, { recursive: true, force: true });
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
