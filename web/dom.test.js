import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";

// dom.js reaches for `document` and `Node` as globals, the way a module loaded by a page
// does. They have to exist before it is imported, which is why this import is dynamic.
const page = new JSDOM("<!doctype html><body></body>");
globalThis.document = page.window.document;
globalThis.Node = page.window.Node;

const { el, wanted, keyOf, comparable, morph, morphChildren } = await import("./dom.js");

/** A container holding the nodes a renderer produced, which is what morphChildren takes. */
const tree = (...children) => el("div", {}, ...children);

// --- el ---------------------------------------------------------------------------------

test("text goes in as text, never as markup", () => {
  // Device names, group names and error strings come from devices and from operators, and
  // this page renders them beside a credential.
  const node = el("span", {}, "<img src=x onerror=alert(1)>");
  assert.equal(node.children.length, 0);
  assert.equal(node.textContent, "<img src=x onerror=alert(1)>");
});

test("a child a renderer declined to produce leaves nothing behind", () => {
  // `replaceChildren` stringifies what it is given, so a panel that renders as null for
  // somebody without the permission for it once put the word "null" on their screen.
  const node = el("div", {}, null, "kept", undefined, false, el("b", {}, "also kept"));
  assert.equal(node.childNodes.length, 2);
  assert.ok(!node.textContent.includes("null"));
  assert.ok(!node.textContent.includes("false"));
});

test("wanted() drops the same things at the top level", () => {
  assert.deepEqual(wanted([null, "a", undefined, false, "b"]), ["a", "b"]);
});

// --- what counts as the same node ---------------------------------------------------------

test("two elements with different keys are not interchangeable", () => {
  // The property the Revoke/Forget bug turned on: same tag, same class, different job.
  const revoke = el("button", { class: "danger", "data-key": "revoke" }, "Revoke");
  const forget = el("button", { class: "danger", "data-key": "forget" }, "Forget");
  assert.equal(comparable(revoke, forget), false);
  assert.equal(keyOf(revoke), "revoke");
});

test("a different tag is never comparable, keys or no keys", () => {
  assert.equal(comparable(el("button", {}, "x"), el("a", {}, "x")), false);
});

// --- morphChildren ------------------------------------------------------------------------

test("a node is not reused for a differently keyed child, so its listener cannot survive", () => {
  // This is the bug, at the unit level. Before both buttons were keyed they were
  // comparable(), the reconciler matched them by position, relabelled the live node and
  // kept the old click listener — so the page offered to erase a device and revoked it.
  const live = el("td", {});
  const revoke = el("button", { class: "danger", "data-key": "revoke" }, "Revoke");
  const fired = [];
  revoke.addEventListener("click", () => fired.push("revoke"));
  live.append(revoke);

  const forget = el("button", { class: "danger", "data-key": "forget" }, "Forget");
  forget.addEventListener("click", () => fired.push("forget"));

  morphChildren(live, tree(forget));

  const button = live.querySelector("button");
  assert.equal(button.textContent, "Forget");
  button.dispatchEvent(new page.window.MouseEvent("click"));
  assert.deepEqual(fired, ["forget"], "the surviving listener must be the new one");
});

test("a keyed child is found wherever it moved to, rather than rewritten", () => {
  // Devices with faults sort to the top, so the row somebody is reading moves at exactly
  // the moment something has gone wrong.
  const live = el("tbody", {});
  const rows = ["a", "b", "c"].map((k) => el("tr", { "data-key": k }, k));
  live.append(...rows);

  morphChildren(live, tree(
    el("tr", { "data-key": "c" }, "c"),
    el("tr", { "data-key": "a" }, "a"),
    el("tr", { "data-key": "b" }, "b"),
  ));

  assert.deepEqual([...live.children].map((n) => n.getAttribute("data-key")), ["c", "a", "b"]);
  // The same three elements, moved — not three new ones holding the same text.
  assert.equal(live.children[0], rows[2]);
  assert.equal(live.children[1], rows[0]);
  assert.equal(live.children[2], rows[1]);
});

test("unkeyed children are matched by position, which is right for fixed furniture", () => {
  const live = el("tr", {}, el("td", {}, "name"), el("td", {}, "old"));
  const cells = [...live.children];
  morphChildren(live, tree(el("td", {}, "name"), el("td", {}, "new")));
  assert.equal(live.children[1], cells[1], "the cell was updated, not replaced");
  assert.equal(live.children[1].textContent, "new");
});

test("a child that is no longer wanted is removed", () => {
  const live = el("ul", {}, el("li", { "data-key": "a" }, "a"), el("li", { "data-key": "b" }, "b"));
  morphChildren(live, tree(el("li", { "data-key": "a" }, "a")));
  assert.equal(live.children.length, 1);
  assert.equal(live.children[0].getAttribute("data-key"), "a");
});

test("a node a click put on the page outlives a render that knows nothing about it", () => {
  // The error shown against the control that failed. It belongs to no render, so no render
  // takes it away; it removes itself on a timer.
  //
  // Defended twice, and this asserts the property rather than either mechanism: the cursor
  // steps over it while children are matched, and the sweep at the end refuses to remove
  // one. Take away either and this still passes; take away both and it fails, which is the
  // level worth pinning.
  const live = el("td", {}, el("button", { "data-key": "act" }, "Act"));
  live.append(el("span", { class: "error", "data-transient": "" }, "went wrong"));

  morphChildren(live, tree(el("button", { "data-key": "act" }, "Act")));

  assert.ok(live.querySelector("[data-transient]"), "the transient node was swept away");
});

// --- morph --------------------------------------------------------------------------------

test("a control with a write in flight is left exactly as the click left it", () => {
  // Handing back an enabled button for an action already under way is how somebody mints a
  // second enrolment token nobody asked for.
  const live = el("button", { "data-busy": "", disabled: "" }, "…");
  morph(live, el("button", {}, "Create an enrolment token"));
  assert.equal(live.textContent, "…");
  assert.ok(live.hasAttribute("data-busy"));
  assert.ok(live.hasAttribute("disabled"));
});

test("an attribute that is gone from the wanted node is removed from the live one", () => {
  const live = el("div", { class: "panel attention", title: "stale" }, "x");
  morph(live, el("div", { class: "panel" }, "x"));
  assert.equal(live.className, "panel");
  assert.equal(live.hasAttribute("title"), false);
});

test("the picker keeps naming the network on screen", () => {
  // Which option is selected is a property, not an attribute, so the attribute loop cannot
  // see it. It has to be read *before* the children are reconciled, because morphChildren
  // takes unmatched nodes out of `next` as it uses them.
  //
  // The live options deliberately do not match the wanted ones — a network appearing or
  // going away is what makes this path run. When every option matches, the wanted nodes are
  // left in `next` and a late read still finds the value, which is a version of this test
  // that passes whether or not the ordering is right.
  const live = el("select", {}, el("option", { value: "old", "data-key": "old" }, "old"));
  live.value = "old";

  const next = el("select", {},
    el("option", { value: "one", "data-key": "one" }, "one"),
    el("option", { value: "two", "data-key": "two" }, "two"));
  next.value = "two";

  morph(live, next);

  assert.deepEqual([...live.options].map((o) => o.value), ["one", "two"]);
  assert.equal(live.value, "two");
});

test("a textarea keeps what somebody typed into it", () => {
  // Its text is a child node, so a render that redraws the panel would otherwise reconcile
  // it back to whatever the page last decided it should be — every few seconds, under
  // somebody's cursor.
  const live = el("textarea", { "data-key": "policy" }, "original");
  live.value = "half a sentence somebody is still writing";

  morph(live, el("textarea", { "data-key": "policy" }, "half a sentence somebody is still writing"));
  assert.equal(live.value, "half a sentence somebody is still writing");
});

test("a textarea does take a value the page deliberately changed", () => {
  const live = el("textarea", { "data-key": "policy" }, "old");
  live.value = "old";
  morph(live, el("textarea", { "data-key": "policy" }, "loaded from the control plane"));
  assert.equal(live.value, "loaded from the control plane");
});
