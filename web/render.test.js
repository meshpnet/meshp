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
