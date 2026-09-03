/**
 * Building and updating DOM, with nothing in it that knows about meshp.
 *
 * Split out of app.js so it can be imported by a test without a page: everything here is a
 * function of its arguments, there is no module state, and nothing reads `view`. That is the
 * whole reason this file exists — the reconciler below is where both of this page's real
 * bugs have been, and neither was found by anything other than a person clicking.
 *
 * show() and update() stayed in app.js. They are the same operations bound to the one
 * element the page draws into, which is exactly the dependency this file is avoiding.
 */

// --- DOM ----------------------------------------------------------------------------

/**
 * Builds an element. Text always goes in as text, never as markup: device names, group
 * names and error strings come from devices and from operators, and this page renders
 * them beside a credential.
 */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "hidden") node.hidden = Boolean(value);
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

/**
 * Drops the children a renderer declined to produce.
 *
 * Nullish children go, the same way el() drops them — and for a reason that only appeared
 * once the page had controls that are absent for some people. `replaceChildren` stringifies
 * what it is given, so a panel that renders as null for somebody without the permission for
 * it put the word "null" on their screen.
 */
function wanted(nodes) {
  return nodes.flat().filter((node) => node !== null && node !== undefined && node !== false);
}

// --- keeping the page still -------------------------------------------------------------
//
// The polled view is redrawn every few seconds on a screen somebody is reading. Replacing
// it wholesale is the obvious way to do that, and it is what this file did while the page
// could only be read. It stopped being tenable when the page gained controls: destroying a
// node takes with it a half-made text selection, a click that straddles the redraw, and the
// focus ring.
//
// So the polled view is updated in place. Renderers are unchanged and still describe the
// whole page — nothing above this line knows any of it is happening — and morph() works out
// the difference. Three things it is careful about, each of them a consequence of a node now
// outliving the render that built it:
//
//   * **A list that reorders needs keys.** Devices with faults sort to the top, so the row
//     somebody is reading moves at exactly the moment something has gone wrong. `data-key`
//     says which row is which. Without it, one device developing a fault would rewrite every
//     row between it and the top, which is the bug this is here to fix wearing a smaller hat.
//   * **A listener outlives the render that attached it.** It must not close over the data
//     it was built beside, because that data is now old. A control that acts on something
//     reads what it is acting on at the moment it is clicked.
//   * **A control with a write in flight is not the page's to redraw.** It has been disabled
//     and relabelled by a click that has not finished.
//
// This is the hand-written reconciliation ADR-0022 §3 anticipated, in one place rather than
// spread through twenty renderers. It is deliberately not a framework: it has no components,
// no state and no lifecycle, and it is only ever called with a tree somebody just built.

/** Whether this element's current contents live in a property rather than in its markup. */
function holdsAValue(node) {
  return node.tagName === "SELECT" || node.tagName === "TEXTAREA";
}

/** What identifies a node between renders, where its position is not enough. */
function keyOf(node) {
  return node.nodeType === Node.ELEMENT_NODE ? node.getAttribute("data-key") : null;
}

/**
 * Something a click put on the page rather than a render — the error shown against the
 * control that failed. It belongs to no render, so no render takes it away; it removes
 * itself on a timer. Without this an error would last until the next poll, which is to say
 * about long enough to notice and not long enough to read.
 */
function isTransient(node) {
  return node.nodeType === Node.ELEMENT_NODE && node.hasAttribute("data-transient");
}

/** Whether a node that is here can become the one that is wanted, or has to be replaced. */
function comparable(live, next) {
  if (live.nodeType !== next.nodeType) return false;
  if (live.nodeType !== Node.ELEMENT_NODE) return true;
  return live.tagName === next.tagName && keyOf(live) === keyOf(next);
}

/** Makes the node that is here into the one that is wanted, without replacing it. */
function morph(live, next) {
  if (live.nodeType !== Node.ELEMENT_NODE) {
    if (live.nodeValue !== next.nodeValue) live.nodeValue = next.nodeValue;
    return;
  }
  // Left exactly as the click left it. Handing back an enabled button for an action already
  // under way is how somebody mints a second enrolment token nobody asked for.
  if (live.hasAttribute("data-busy")) return;

  for (const attr of next.attributes) {
    if (live.getAttribute(attr.name) !== attr.value) live.setAttribute(attr.name, attr.value);
  }
  for (const attr of [...live.attributes]) {
    if (!next.hasAttribute(attr.name)) live.removeAttribute(attr.name);
  }
  // What a control currently holds is a property, not an attribute, so the loop above
  // cannot see it — without this the picker would go on naming the network somebody
  // navigated away from, and a textarea would keep whatever text it was first drawn with.
  //
  // Read before the children are reconciled, not after: morphChildren() takes nodes out of
  // `next` as it uses them, so by the time it returns `next` no longer holds the option
  // this is asking about. A textarea's text is its child, which is the same problem.
  //
  // Assigned only when it differs. A textarea is a thing somebody types into, and writing
  // the same string back would move their cursor to the end every few seconds.
  const held = holdsAValue(live) ? next.value : null;
  morphChildren(live, next);
  if (held !== null && live.value !== held) live.value = held;
}

/**
 * Reconciles one element's children against what is wanted.
 *
 * Keyed children are found by key wherever they are, so a list that reorders moves nodes
 * rather than rewriting them. Unkeyed children are matched by position, which is right for
 * the fixed furniture — a heading, a label, the cells of a row — that never moves.
 *
 * Nodes are taken out of `next` as they are used. That tree was built by the caller for this
 * call and is discarded afterwards.
 */
function morphChildren(live, next) {
  const keyed = new Map();
  for (let node = live.firstChild; node; node = node.nextSibling) {
    const key = keyOf(node);
    if (key !== null && !keyed.has(key)) keyed.set(key, node);
  }

  let cursor = live.firstChild;
  const skipHeld = () => {
    while (cursor && isTransient(cursor)) cursor = cursor.nextSibling;
  };
  skipHeld();

  for (const want of [...next.childNodes]) {
    const key = keyOf(want);
    let match = null;
    if (key !== null) {
      const candidate = keyed.get(key);
      keyed.delete(key);
      if (candidate && comparable(candidate, want)) match = candidate;
    } else if (cursor && keyOf(cursor) === null && comparable(cursor, want)) {
      match = cursor;
    }

    if (match === null) {
      live.insertBefore(want, cursor);
      continue;
    }
    if (match === cursor) {
      cursor = cursor.nextSibling;
      skipHeld();
    } else {
      live.insertBefore(match, cursor);
    }
    morph(match, want);
  }

  while (cursor) {
    const stale = cursor;
    cursor = cursor.nextSibling;
    if (!isTransient(stale)) live.removeChild(stale);
  }
}

export { el, wanted, keyOf, isTransient, comparable, morph, morphChildren, holdsAValue };
