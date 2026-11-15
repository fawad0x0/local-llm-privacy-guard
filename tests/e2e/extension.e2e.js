// End-to-end tests: loads the built extension into Chromium and drives a mock chat page that is
// served at https://chatgpt.com/ so the real content scripts inject exactly as on the live site.
// The review dialog lives in a closed shadow root (by design), so tests drive it with the keyboard.
// Run: npm run test:e2e   (requires: npx playwright install chromium)
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { chromium } = require("playwright");
const { build } = require("../../scripts/build");

const MOCK = fs.readFileSync(path.join(__dirname, "mock-chat.html"), "utf8");
const URL_RICH = "https://chatgpt.com/?mode=rich";
const URL_PLAIN = "https://chatgpt.com/?mode=textarea";

let context;
let worker;

async function setSettings(patch) {
  await worker.evaluate(async p => {
    const cur = (await chrome.storage.local.get("settings")).settings || {};
    await chrome.storage.local.set({ settings: { ...cur, ...p } });
  }, patch);
}

async function openPage(url = URL_RICH) {
  const page = await context.newPage();
  await page.goto(url);
  await page.waitForFunction(() => document.querySelector('privacy-guard-ui[data-privacy-guard="badge"]')); // badge mounted = content script ready
  return page;
}

const editorSel = page => (page.url().includes("textarea") ? "#plain" : "#prompt-textarea");
const DIALOG = 'privacy-guard-ui[data-privacy-guard="dialog"]';
const dialogOpen = page => page.evaluate(sel => !!document.querySelector(sel), DIALOG);
const sent = page => page.$$eval("#log li", els => els.map(e => e.textContent));

async function type(page, text) {
  await page.click(editorSel(page));
  await page.keyboard.insertText(text);
}

async function waitDialog(page, open = true) {
  await page.waitForFunction(([sel, o]) => !!document.querySelector(sel) === o, [DIALOG, open], { timeout: 5000 });
}

test.before(async () => {
  const ext = build(fs.mkdtempSync(path.join(os.tmpdir(), "pg-ext-")));
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "pg-profile-"));
  context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`]
  });
  await context.route("https://chatgpt.com/**", route =>
    route.fulfill({ status: 200, contentType: "text/html", body: MOCK })
  );
  worker = context.serviceWorkers()[0] || (await context.waitForEvent("serviceworker"));
});

test.after(async () => {
  if (context) await context.close();
});

test.beforeEach(async () => {
  await worker.evaluate(() => chrome.storage.local.clear());
});

test("clean message is sent without interruption", async () => {
  const page = await openPage();
  await type(page, "How do I reverse a list in Python?");
  await page.keyboard.press("Enter");
  assert.deepEqual(await sent(page), ["How do I reverse a list in Python?"]);
  assert.equal(await dialogOpen(page), false);
  await page.close();
});

test("secret is caught on Enter and the sanitized text is sent", async () => {
  const page = await openPage();
  await type(page, "my config DB_PASSWORD=hunter2pass please help");
  await page.keyboard.press("Enter");
  await waitDialog(page);
  assert.deepEqual(await sent(page), [], "original must not be sent while reviewing");
  await page.keyboard.press("Enter"); // primary button "Send sanitized" has focus
  await page.waitForFunction(() => document.querySelectorAll("#log li").length === 1);
  assert.deepEqual(await sent(page), ["my config DB_PASSWORD=[PASSWORD_1] please help"]);
  await page.close();
});

test("send button click is intercepted too", async () => {
  const page = await openPage();
  await type(page, "server is 10.0.3.7 and mail ali@acme.pk");
  await page.click("#send");
  await waitDialog(page);
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => document.querySelectorAll("#log li").length === 1);
  assert.deepEqual(await sent(page), ["server is [IP_1] and mail [EMAIL_1]"]);
  await page.close();
});

test("Escape cancels: nothing is sent and the text stays in the editor", async () => {
  const page = await openPage();
  await type(page, "postgres://admin:S3cretPw@db.internal/app");
  await page.keyboard.press("Enter");
  await waitDialog(page);
  await page.keyboard.press("Escape");
  await waitDialog(page, false);
  assert.deepEqual(await sent(page), []);
  assert.match(await page.textContent("#prompt-textarea"), /S3cretPw/);
  await page.close();
});

test("critical findings block 'send original' until the user types SEND", async () => {
  const page = await openPage();
  await type(page, "postgres://admin:S3cretPw@db.internal/app");
  await page.keyboard.press("Enter");
  await waitDialog(page);
  // Focus order: checkboxes..., details summary, textarea, confirm input, Cancel, Send original, Send sanitized.
  // Shift+Tab from the primary button reaches "Send original anyway", which must be disabled (skipped).
  await page.keyboard.press("Shift+Tab");
  await page.keyboard.press("Enter"); // lands on Cancel because "Send original" is disabled
  await waitDialog(page, false);
  assert.deepEqual(await sent(page), []);
  await page.close();
});

test("typing SEND unlocks 'send original anyway' for blocked items", async () => {
  const page = await openPage();
  await type(page, "postgres://admin:S3cretPw@db.internal/app");
  await page.keyboard.press("Enter");
  await waitDialog(page);
  await page.keyboard.press("Shift+Tab"); // Cancel (Send original is disabled and skipped)
  await page.keyboard.press("Shift+Tab"); // confirm input
  await page.keyboard.type("SEND");
  await page.keyboard.press("Tab"); // Cancel
  await page.keyboard.press("Tab"); // Send original anyway (now enabled)
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => document.querySelectorAll("#log li").length === 1);
  assert.deepEqual(await sent(page), ["postgres://admin:S3cretPw@db.internal/app"]);
  await page.close();
});

test("'Review every prompt' no longer blocks sending forever (v0.1 bug)", async () => {
  await setSettings({ reviewAll: true });
  const page = await openPage();
  await type(page, "hello there");
  await page.keyboard.press("Enter");
  await waitDialog(page);
  await page.keyboard.press("Enter"); // primary is "Send" when nothing was found
  await page.waitForFunction(() => document.querySelectorAll("#log li").length === 1);
  assert.deepEqual(await sent(page), ["hello there"]);
  await page.close();
});

test("pasting an .env file is reviewed before it reaches the editor", async () => {
  const page = await openPage();
  await page.click("#prompt-textarea");
  await page.evaluate(() => {
    const dt = new DataTransfer();
    dt.setData("text/plain", "DB_HOST=db01.corp.local\nDB_PASSWORD=hunter2pass\nPORT=3000");
    document
      .getElementById("prompt-textarea")
      .dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }));
  });
  await waitDialog(page);
  assert.equal((await page.textContent("#prompt-textarea")).trim(), "", "nothing pasted yet");
  await page.keyboard.press("Enter"); // "Paste sanitized"
  await waitDialog(page, false);
  const text = await page.evaluate(() => document.getElementById("prompt-textarea").innerText);
  assert.match(text, /DB_HOST=\[HOST_1\]/);
  assert.match(text, /DB_PASSWORD=\[PASSWORD_1\]/);
  assert.doesNotMatch(text, /hunter2pass/);
  await page.close();
});

test("uploading an .env file offers a sanitized copy", async () => {
  const page = await openPage();
  await page.setInputFiles("#file", {
    name: ".env",
    mimeType: "text/plain",
    buffer: Buffer.from("DB_PASSWORD=hunter2pass\nPORT=3000\n")
  });
  await waitDialog(page);
  assert.equal(await page.$$eval("#files li", e => e.length), 0, "page must not receive the file yet");
  await page.keyboard.press("Enter"); // "Upload sanitized copies"
  await page.waitForFunction(() => document.querySelectorAll("#files li").length === 1);
  const uploaded = await page.textContent("#files li");
  assert.match(uploaded, /^\.env => DB_PASSWORD=\[PASSWORD_1\]/);
  assert.doesNotMatch(uploaded, /hunter2pass/);
  await page.close();
});

test("clean file uploads pass straight through", async () => {
  const page = await openPage();
  await page.setInputFiles("#file", { name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("just notes") });
  await page.waitForFunction(() => document.querySelectorAll("#files li").length === 1);
  assert.equal(await page.textContent("#files li"), "notes.txt => just notes");
  assert.equal(await dialogOpen(page), false);
  await page.close();
});

test("plain textarea composer works the same way", async () => {
  const page = await openPage(URL_PLAIN);
  await type(page, "token: ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
  await page.keyboard.press("Enter");
  await waitDialog(page);
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => document.querySelectorAll("#log li").length === 1);
  assert.deepEqual(await sent(page), ["token: [GITHUB_TOKEN_1]"]);
  await page.close();
});

test("disabling the site turns protection off", async () => {
  await setSettings({ disabledSites: ["chatgpt.com"] });
  const page = await context.newPage();
  await page.goto(URL_RICH);
  await page.waitForTimeout(500);
  await type(page, "DB_PASSWORD=hunter2pass");
  await page.keyboard.press("Enter");
  assert.deepEqual(await sent(page), ["DB_PASSWORD=hunter2pass"]);
  await page.close();
});

test("'Show real values' restores originals on screen only", async () => {
  const page = await openPage();
  await type(page, "ping ali@acme.pk");
  await page.keyboard.press("Enter");
  await waitDialog(page);
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => document.querySelectorAll("#log li").length === 1);
  assert.equal(await page.textContent("#reply"), "You said: ping [EMAIL_1]");
  // The reveal button is fixed at top-right inside a closed shadow root: click by position.
  const vw = page.viewportSize().width;
  await page.mouse.click(vw - 60, 85);
  await page.waitForFunction(() => document.getElementById("reply").textContent.includes("ali@acme.pk"));
  assert.equal(await page.textContent("#reply"), "You said: ping ali@acme.pk");
  await page.close();
});
