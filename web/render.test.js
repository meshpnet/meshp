import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";

// app.js reads the page's elements at module scope and used to start polling at import.
// The bootstrap now lives in main.js, so this only needs a document that has the elements.
const page = new JSDOM(
  `<!doctype html><body><div id="view"></div><span id="freshness"></span>
   <button id="signout"></button></body>`,
);
globalThis.document = page.window.document;
globalThis.Node = page.window.Node;
globalThis.window = page.window;

const { renderDevices, revokeButton, forgetButton, organizationOf, may, fetchPermissions } =
  await import("./app.js");
const { morphChildren, el } = await import("./dom.js");

const ORG = "cccccccc-0000-0000-0000-000000000001";
const NET = "11111111-2222-3333-4444-555555555555";

/** A device row as the overview endpoint sends one. */
const device = (over = {}) => ({
  membership_id: "aaaaaaaa-0000-0000-0000-000000000001",
  device_id: "dddddddd-0000-0000-0000-000000000001",
  device_name: "bravo",
  state: "active",
  connected: true,
  applied_version: 7,
  reported_version: 7,
  address_v4: "100.80.0.3",
  tunnel: { peers: 3, talking: 3, relayed: 0 },
  faults: [],
  ...over,
});

/**
 * Grants a permission set by answering the request app.js actually makes for it.
 *
 * Node's Response, not jsdom's — jsdom implements no fetch and no Response, so building
 * one from `page.window` throws, fetchPermissions swallows it, and every permission comes
 * back denied. Which looks exactly like a working test for anything asserting that a
 * control is absent.
 */
async function granting(...names) {
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ permissions: names, unlimited: false }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  await fetchPermissions(NET);
  // Refuses to run the rest of a test against a permission set that was never granted.
  for (const name of names) {
    if (!may(name)) throw new Error(`granting(${name}) did not take effect`);
  }
}

test("permissions come from the control plane, and decide nothing else", async () => {
  await granting("network.devices.revoke");
  assert.equal(may("network.devices.revoke"), true);
  assert.equal(may("organization.devices.forget"), false);
});

test("a control somebody may not use is never drawn", async () => {
  await granting();
  assert.equal(revokeButton(device()), null);
  assert.equal(forgetButton(device({ state: "revoked" }), ORG), null);
});

// The wiring half of #218. dom.test.js proves that keys stop a node being reused; this
// proves the buttons this page builds actually carry them, which was the part only a
// person walking docs/testing/the-page.md could check.
test("the two device actions are keyed apart", async () => {
  await granting("network.devices.revoke", "organization.devices.forget");

  const revoke = revokeButton(device());
  const forget = forgetButton(device({ state: "revoked" }), ORG);

  assert.equal(revoke.dataset.key, "revoke");
  assert.equal(forget.dataset.key, "forget");
  assert.notEqual(revoke.dataset.key, forget.dataset.key);
});

test("each action carries the id its endpoint is addressed by", async () => {
  await granting("network.devices.revoke", "organization.devices.forget");
  const d = device({ state: "revoked" });

  // Revoking is per membership under a network; forgetting is per device under an
  // organisation (ADR-0004). Sending one id where the other belongs would address a real
  // route with a real-looking id and be refused as a 404 rather than as a mistake.
  assert.equal(revokeButton(device()).dataset.membership, d.membership_id);
  assert.equal(forgetButton(d, ORG).dataset.device, d.device_id);
});

test("forgetting is offered only once a device is out of the network", async () => {
  await granting("network.devices.revoke", "organization.devices.forget");
  assert.equal(forgetButton(device({ state: "active" }), ORG), null);
  assert.ok(forgetButton(device({ state: "revoked" }), ORG));
  // And without an organisation there is nothing to address the request to.
  assert.equal(forgetButton(device({ state: "revoked" }), null), null);
});

test("revoking is offered only while a device is still in the network", async () => {
  await granting("network.devices.revoke");
  assert.ok(revokeButton(device({ state: "active" })));
  assert.equal(revokeButton(device({ state: "revoked" })), null);
});

// Manual check 8, run by a machine: a row whose device has just been revoked must come back
// with a different button, and the reconciler must not hand the old node over with it.
test("a row that turns from active to revoked swaps the button rather than relabelling it", async () => {
  await granting("network.devices.revoke", "organization.devices.forget");

  const live = el("tbody", {});
  morphChildren(live, el("div", {}, renderDevices([device()], ORG).querySelector("tbody").children[0]));

  const before = live.querySelector("td.actions button");
  assert.equal(before.textContent, "Revoke");

  const next = renderDevices([device({ state: "revoked", connected: false })], ORG)
    .querySelector("tbody").children[0];
  morphChildren(live, el("div", {}, next));

  const after = live.querySelector("td.actions button");
  assert.equal(after.textContent, "Forget");
  assert.notEqual(after, before, "the Revoke node was reused, and its listener with it");
});

test("the organisation is read from the network the page is showing", () => {
  const data = { network: { id: NET } };
  const networks = [{ id: NET, organization_id: ORG }, { id: "other", organization_id: "x" }];
  assert.equal(organizationOf(data, networks), ORG);
  assert.equal(organizationOf({ network: { id: "missing" } }, networks), null);
  assert.equal(organizationOf(data, undefined), null);
});

// --- the policy dry-run -------------------------------------------------------------------

const { renderPolicyTest } = await import("./app.js");

test("the dry-run panel is absent for somebody who may not publish a policy", async () => {
  await granting("network.devices.revoke");
  assert.equal(renderPolicyTest([device()]), null);
});

test("the dry-run offers only devices a policy could apply to", async () => {
  await granting("network.acl.write");

  // A revoked device is not among the devices a policy resolves against, so offering it
  // would be offering a question the control plane answers with a refusal.
  assert.equal(renderPolicyTest([device({ state: "revoked" })]), null);

  const panel = renderPolicyTest([
    device({ state: "active", device_name: "alpha" }),
    device({ state: "revoked", device_name: "bravo", membership_id: "m-2" }),
  ]);
  const options = [...panel.querySelectorAll("option")].map((o) => o.textContent);
  assert.deepEqual(options, ["alpha"]);
});

test("the dry-run addresses a device by its membership, which is what the route takes", async () => {
  await granting("network.acl.write");
  const d = device();
  const panel = renderPolicyTest([d]);
  assert.equal(panel.querySelector("option").value, d.membership_id);
});

// --- the policy editor --------------------------------------------------------------------

const { renderPolicyEditor, diffLines } = await import("./app.js");

test("the editor is absent for somebody who may not publish a policy", async () => {
  await granting("network.devices.revoke");
  assert.equal(renderPolicyEditor(), null);
});

test("the editor is a box holding the document, not a form describing it", async () => {
  await granting("network.acl.write");
  const panel = renderPolicyEditor();
  const box = panel.querySelector("textarea#acl-document");
  assert.ok(box, "there is no document to edit");
  // Keyed, so a poll reconciles it rather than replacing the node somebody is typing into.
  assert.equal(box.dataset.key, "acl-document");
});

test("a diff shows the line that changed and the ones around it", () => {
  // Long enough that trimming matters: a real policy is dozens of lines and the change is
  // one of them, so showing the document back is showing the box above again.
  const lead = Array.from({ length: 20 }, (_, i) => `  "pad${i}": ${i},`).join("\n");
  const rows = diffLines(`{\n${lead}\n  "comment": "old",\n  "rules": []\n}\n`,
                         `{\n${lead}\n  "comment": "new",\n  "rules": []\n}\n`);
  const marks = rows.map((r) => r.mark + r.text.trim());
  assert.ok(marks.includes(`-"comment": "old",`), `no removal: ${marks.join(" | ")}`);
  assert.ok(marks.includes(`+"comment": "new",`), `no addition: ${marks.join(" | ")}`);
  assert.ok(rows.filter((r) => r.kind === "same").length <= 4,
    `${rows.filter((r) => r.kind === "same").length} context lines from a 24-line document`);
});

test("a first policy is all additions", () => {
  const rows = diffLines("", '{\n  "version": 1\n}\n');
  assert.equal(rows.filter((r) => r.kind === "gone").length, 0);
  assert.ok(rows.some((r) => r.kind === "new"));
});

test("an unchanged document produces no marks", () => {
  const doc = '{\n  "version": 1\n}\n';
  const rows = diffLines(doc, doc);
  assert.equal(rows.filter((r) => r.kind !== "same").length, 0);
});

// A rule inserted in the middle must read as an insertion, not as everything below it
// being rewritten — the same property the CLI's diff has, for the same reason.
test("an insertion does not rewrite what follows", () => {
  const rows = diffLines("a\nb\nc\nd\ne\n", "a\nb\nINSERTED\nc\nd\ne\n");
  assert.equal(rows.filter((r) => r.kind === "gone").length, 0);
  assert.equal(rows.filter((r) => r.kind === "new").length, 1);
});

// Two changes with unchanged lines between them, which trimming the ends cannot collapse.
// Without matching by subsequence the middle reads as five lines replaced by five rather
// than as two lines that moved — and the test above cannot tell, because one change at the
// edge is trimmed away before the subsequence is reached.
test("lines between two changes are recognised rather than rewritten", () => {
  const rows = diffLines("a\nb\nc\nd\ne\nf\ng\n", "a\nX\nc\nd\ne\nY\ng\n");
  const gone = rows.filter((r) => r.kind === "gone").map((r) => r.text);
  const added = rows.filter((r) => r.kind === "new").map((r) => r.text);
  assert.deepEqual(gone, ["b", "f"], `removed ${gone.join(",")}`);
  assert.deepEqual(added, ["X", "Y"], `added ${added.join(",")}`);
});

// The subsequence is O(n*m) over text somebody is typing into, so it is bounded.
test("two wholly different documents are summarised rather than compared", () => {
  const before = Array.from({ length: 500 }, (_, i) => `old ${i}`).join("\n");
  const after = Array.from({ length: 500 }, (_, i) => `new ${i}`).join("\n");
  const rows = diffLines(before, after);
  assert.ok(rows.some((r) => r.text.includes("lines replaced by")), "it tried the full compare");
});

// --- the network, as a picture ------------------------------------------------------------

const { renderTopology } = await import("./app.js");

/** A network of n devices, with the given indexes faulted and carrying. */
function network(n, { faults = [], carrying = [] } = {}) {
  const devices = Array.from({ length: n }, (_, i) => ({
    membership_id: `m${i}`,
    device_id: `d${i}`,
    device_name: `dev${i}`,
    state: "active",
    connected: true,
    faults: faults.includes(i) ? [{ message: "has not applied its configuration" }] : [],
  }));
  const data = {
    route_groups: carrying.length
      ? [{ slug: "office", advertisers: carrying.map((i) => ({ membership_id: `m${i}` })) }]
      : [],
  };
  return { data, devices };
}

const drawOf = (n, opts) => {
  const { data, devices } = network(n, opts);
  return renderTopology(data, devices).querySelector("svg");
};

// The property that matters most. Everything relays (ADR-0002), so a line between two
// devices would be a path that does not exist — the one thing a diagram of a network must
// not draw. Every line here starts at the hub.
test("no line joins two devices, because no such path exists", () => {
  const svg = drawOf(8, { faults: [1], carrying: [0, 2] });
  const hub = svg.querySelector("circle.hub");
  const cx = Number(hub.getAttribute("cx"));
  const cy = Number(hub.getAttribute("cy"));

  const lines = [...svg.querySelectorAll("line")];
  assert.ok(lines.length > 0, "nothing was drawn");
  for (const line of lines) {
    assert.equal(Number(line.getAttribute("x1")), cx, "a line does not start at the relay");
    assert.equal(Number(line.getAttribute("y1")), cy, "a line does not start at the relay");
  }
});

test("a small network draws every device", () => {
  assert.equal(drawOf(6).querySelectorAll("circle.node").length, 6);
});

test("only devices worth naming are named", () => {
  const svg = drawOf(6, { faults: [1], carrying: [0] });
  const labels = [...svg.querySelectorAll(".node-label")].map((t) => t.textContent);
  assert.equal(labels.length, 2, `labelled ${labels.join(", ")}`);
  assert.ok(labels.some((l) => l.startsWith("dev1")), "the faulted device is not named");
  assert.ok(labels.some((l) => l.includes("office")), "the carrier does not say what it carries");
});

// At the five hundred devices one overview carries, a ring of five hundred dots is three
// pixels apart and answers nothing.
test("a large network draws what matters and counts the rest", () => {
  const svg = drawOf(500, { faults: [1], carrying: [0, 2] });
  assert.equal(svg.querySelectorAll("circle.node.many").length, 1);
  // Three notable devices and the one standing for everyone else.
  assert.equal(svg.querySelectorAll("circle.node").length, 4);
  const summary = [...svg.querySelectorAll(".node-label")].find((t) => t.textContent.includes("more"));
  assert.ok(summary, "the devices not drawn are not accounted for");
  assert.ok(summary.textContent.startsWith("497"), `said ${summary.textContent}`);
});

// Colour is never the only signal — a stated rule of this stylesheet, and a fault is the
// one thing on the page somebody must not miss.
test("a fault carries a mark as well as a colour", () => {
  const svg = drawOf(6, { faults: [1] });
  assert.equal(svg.querySelectorAll(".node-mark").length, 1);
  assert.equal(svg.querySelector(".node-mark").textContent, "!");
});

test("the diagram is sized to what it drew, so its labels are never clipped", () => {
  const svg = drawOf(6, { carrying: [0] });
  const [x, y, w, h] = svg.getAttribute("viewBox").split(" ").map(Number);
  assert.ok(w > 0 && h > 0);
  // The width and height attributes carry the same size, so a user unit is a pixel and the
  // text renders at the size it is set in rather than scaled to the container.
  assert.equal(Number(svg.getAttribute("width")), Math.round(w));
  assert.equal(Number(svg.getAttribute("height")), Math.round(h));
});

test("a network with no devices says so rather than drawing an empty ring", () => {
  const panel = renderTopology({ route_groups: [] }, []);
  assert.equal(panel.querySelector("svg"), null);
  assert.match(panel.textContent, /no devices/i);
});
