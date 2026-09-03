// The page (ADR-0022). One network, one question: is anything unreachable, and what is
// carrying for it.
//
// Hand-written ES modules, no framework and no build step, so this file is what runs.
// Three rules it must not break:
//
//   1. It never invents a fact the control plane does not have. In particular it does not
//      say which advertiser is *chosen* — desired state carries an ordered list of
//      pre-authorised candidates and the agent decides which is alive (ADR-0003), so no
//      such fact exists server-side to render.
//   2. It shows its own freshness. A monitoring view that lies about when it last heard
//      anything is worse than no view, so a failed poll makes the page visibly stale
//      rather than leaving old numbers looking current.
//   3. Colour is never the only signal. Anything shown in red says the same thing in words.

const view = document.getElementById("view");
const freshnessEl = document.getElementById("freshness");
const signoutEl = document.getElementById("signout");

/**
 * What this person may do in the network being shown.
 *
 * Fetched once per network rather than per poll — a role changes rarely and the answer is
 * about the caller, not about the network — and used only to decide which controls exist.
 * It is never the enforcement: the API refuses regardless, and a page that believed itself
 * would be a page one edit away from being the security boundary.
 *
 * Empty until it has been read, so a control is absent while the answer is unknown rather
 * than flickering into existence. Absent-then-present is a page loading; present-then-gone
 * is a page that lied.
 */
let permissions = new Set();
let unlimited = false;

/** Whether this person may do something here. */
function may(permission) {
  return unlimited || permissions.has(permission);
}

/**
 * A token this page has just minted, held here rather than only in the DOM.
 *
 * The control plane stores only a hash, so the moment after minting is the only moment that
 * secret exists. It lives in state because every render describes the whole page: a token
 * that existed only in the node it was drawn into would be gone the first time a render
 * did not know to draw it, and somebody would click again and mint another credential
 * nobody can use.
 */
let mintedToken = null;
/** Which network that token was minted for, so moving away clears it. */
let shownFor = null;

/**
 * The last policy dry-run, held here rather than only in the node it was drawn into.
 *
 * Same reason as a minted token: every render describes the whole page, so an answer that
 * lived only in the DOM would vanish the first time a poll redrew the panel — which happens
 * every few seconds, and is exactly when somebody is reading it.
 */
let policyTest = null;

/**
 * The policy as it is being edited, and the one the control plane holds.
 *
 * `policyText` is what is in the box, so a poll redrawing the panel draws what somebody has
 * typed rather than what the network last published. `policyLive` is what to diff against
 * and what tells the difference between "no changes" and "no policy".
 */
let policyText = null;
let policyLive = null;
/** What the control plane said when it refused the last document, shown verbatim. */
let policyError = null;

/** Last successful overview, kept so a failed poll can keep showing it — marked stale. */
let lastGood = null;
/** What was rendered beside it, so the page can redraw itself without polling again. */
let lastNetworks = [];
let lastHistory = null;
/** When that arrived, by this browser's clock. `as_of` is the server's. */
let lastGoodAt = null;
let pollTimer = null;
let freshnessTimer = null;

// --- the API -------------------------------------------------------------------------

/**
 * One call. Errors carry the status and the server's code so a caller can tell an
 * expired session from a network that has gone away.
 */
async function api(path, options = {}) {
  const res = await fetch(path, {
    // The credential is an HttpOnly cookie; no script here ever holds a token.
    credentials: "same-origin",
    ...options,
  });
  const text = await res.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!res.ok) {
    const err = new Error((body && body.message) || `HTTP ${res.status}`);
    err.status = res.status;
    err.code = body && body.error;
    throw err;
  }
  return body;
}

/**
 * What to put in front of a person when a call failed.
 *
 * A fetch that never reached anything rejects with the browser's own wording — "Failed to
 * fetch", or something else entirely depending on the browser — which describes the API
 * this file called rather than what went wrong. Somebody watching a network go down
 * deserves the sentence that is actually true.
 */
function reason(err) {
  return err.status === undefined ? "cannot reach the control plane" : err.message;
}

import { el, wanted, morphChildren } from "./dom.js";


/**
 * Replaces the view.
 *
 * For the views drawn once, in answer to something a person did: signing in, picking a
 * network, an error where a network used to be. The polled view uses update() instead.
 */
function show(...nodes) {
  view.replaceChildren(...wanted(nodes));
}


/** Updates the view in place. The polled path; see above for why it is not show(). */
function update(...nodes) {
  morphChildren(view, el("div", {}, ...wanted(nodes)));
}

// --- what counts as broken ------------------------------------------------------------
//
// Nothing here decides that. The control plane does, and sends `faults` on every device and
// every route group (ADR-0023): there are two consumers of that endpoint and rules kept
// here could only ever be a second opinion that drifts from the commercial layer's. Any
// rule that reappears in this file is a bug.

/** How a device's data plane reads, in words. */
function tunnelSummary(device) {
  // Held by another control-plane replica, which has the device's report and this one does
  // not. Said rather than shown as "not reported yet": a device that has been talking to the
  // replica next door for an hour and one that has never said anything are different, and
  // only the second is worth investigating.
  if (device.reported_by === "another_replica") return "reported to another replica";
  // Absent because the device has not said, which is not the same as having nothing.
  if (!device.tunnel) return device.connected ? "not reported yet" : "—";
  const { peers, talking, relayed } = device.tunnel;
  if (peers === 0) return "no peers";
  const bits = [`${talking} of ${peers} talking`];
  if (relayed) bits.push(`${relayed} relayed`);
  return bits.join(" · ");
}

// --- rendering ------------------------------------------------------------------------

const HEALTH_CLASS = {
  healthy: "ok",
  degraded: "warn",
  unhealthy: "bad",
  offline: "bad",
  unknown: "unknown",
};

function dot(className, label) {
  return el("span", { class: `dot ${className}`, title: label, "aria-hidden": "true" }, "●");
}

function renderVerdict(data, faultCount) {
  const devices = data.devices.length;
  const groups = data.route_groups.length;
  const counted = `${devices} device${devices === 1 ? "" : "s"}, ${groups} route group${groups === 1 ? "" : "s"}`;

  return el(
    "div",
    { class: `panel verdict ${faultCount ? "problems" : ""}`, "data-key": "verdict" },
    el(
      "h1",
      {},
      faultCount
        ? `${faultCount} thing${faultCount === 1 ? "" : "s"} need${faultCount === 1 ? "s" : ""} attention`
        : "No faults reported",
    ),
    el(
      "span",
      { class: "sub" },
      faultCount
        ? counted
        : // Said precisely. The page knows what devices reported and what health checks
          // observed; it does not know that every packet is arriving.
          `${counted} — every device is applying its configuration and every route group has a candidate`,
    ),
  );
}

function renderGroup(group) {
  const faults = group.faults || [];

  const carriers = group.advertisers.map((advertiser) => {
    const health = advertiser.health || "unknown";
    const bits = [`priority ${advertiser.priority}`];
    // What devices say they are using, which is as close to "chosen" as anything gets: the
    // server owns the order and the agent owns the choice (ADR-0003), so this is a count of
    // reports rather than a decision. Shown only when something is using it — zero means
    // "nothing has reported", not "not carrying", and a column of zeroes would read as the
    // second.
    if (advertiser.in_use_by > 0) {
      bits.unshift(`carrying ${advertiser.in_use_by} device${advertiser.in_use_by === 1 ? "" : "s"}`);
    }
    if (advertiser.weight !== 1) bits.push(`weight ${advertiser.weight}`);
    bits.push(health === "unknown" ? "never health checked" : health);
    if (advertiser.admin_state !== "enabled") bits.push(advertiser.admin_state);
    // Named as a control-plane fact, not as an outage, because it is not one.
    if (!advertiser.connected) bits.push("control session down");
    const where = [advertiser.city, advertiser.region].filter(Boolean).join(", ");
    if (where) bits.push(where);

    return el(
      "li",
      { class: `carrier ${advertiser.viable ? "" : "not-viable"}`, "data-key": advertiser.membership_id },
      dot(HEALTH_CLASS[health] || "unknown", health),
      el("span", { class: "who" }, advertiser.device_name),
      el("span", { class: "why" }, bits.join(" · ")),
    );
  });

  return el(
    "div",
    { class: "panel", "data-key": group.id },
    el(
      "div",
      { class: "group" },
      el(
        "div",
        { class: "group-id" },
        el("div", { class: "name" }, group.name || group.slug),
        el("div", { class: "meta" }, `${group.kind} · ${group.selection_mode}`),
        el(
          "ul",
          { class: "prefixes" },
          group.prefixes.map((prefix) => el("li", { "data-key": prefix }, prefix)),
        ),
        group.stable_egress_ip ? el("div", { class: "meta mono" }, `egress ${group.stable_egress_ip}`) : null,
      ),
      el(
        "div",
        {},
        faults.length ? el("div", { class: "nobody" }, faults.map((f) => f.message).join("; ")) : null,
        carriers.length
          ? el("ul", { class: "carriers" }, carriers)
          : el("div", { class: "note" }, "no advertisers"),
      ),
    ),
  );
}

function renderDevices(devices, organizationID) {
  const rows = devices.map((device) => {
    const faults = device.faults || [];
    const addresses = [device.address_v4, device.address_v6].filter(Boolean);

    let stateLabel;
    let stateClass;
    if (device.state !== "active") {
      stateLabel = device.state;
      stateClass = "unknown";
    } else if (device.connected) {
      stateLabel = "connected";
      stateClass = "ok";
    } else {
      stateLabel = "control session down";
      stateClass = "warn";
    }

    // Both numbers, when they disagree. They differ while an acknowledgement is in
    // flight, and somebody chasing a device that looks stuck needs to see which of the
    // two is behind rather than one number that could be either.
    const versions =
      device.reported_version !== undefined && device.reported_version !== device.applied_version
        ? `${device.applied_version} recorded, ${device.reported_version} reported`
        : String(device.applied_version ?? 0);

    return el(
      "tr",
      // Keyed, because this list reorders: a device that develops a fault sorts to the top,
      // which is the moment somebody is most likely to be reading the row it displaced.
      { class: faults.length ? "attention" : "", "data-key": device.membership_id },
      el(
        "td",
        {},
        el("div", {}, device.device_name),
        addresses.length ? el("div", { class: "addr" }, addresses.join("  ")) : null,
      ),
      el("td", {}, dot(stateClass, stateLabel), " ", stateLabel),
      el("td", { class: "note" }, tunnelSummary(device)),
      el("td", { class: "mono" }, versions),
      el(
        "td",
        {},
        faults.length
          ? el(
              "ul",
              { class: "faults" },
              faults.map((fault) => el("li", { "data-key": fault.message }, fault.message)),
            )
          : el("span", { class: "note" }, "—"),
      ),
      // Empty for somebody who may not act, rather than absent: a column that appears and
      // disappears between people makes two screenshots of the same page look like two
      // different products.
      el("td", { class: "actions" }, revokeButton(device), forgetButton(device, organizationID)),
    );
  });

  // Wrapped, so the table scrolls sideways on a narrow screen and the page does not. A
  // body that shifts under a thumb makes every row harder to read, to save a column.
  const table = el(
    "table",
    { class: "devices" },
    el(
      "thead",
      {},
      el(
        "tr",
        {},
        el("th", {}, "Device"),
        el("th", {}, "Control session"),
        el("th", {}, "Tunnel"),
        el("th", {}, "Applied version"),
        el("th", {}, "Reported faults"),
        el("th", { class: "actions" }, ""),
      ),
    ),
    el("tbody", {}, rows),
  );
  return el("div", { class: "scroll" }, table);
}

// --- doing something ---------------------------------------------------------------------
//
// Two write paths, and deliberately only two (ADR-0022 §5, as rewritten by ADR-0024). They
// are the two halves of a device's life — getting one on, and getting one off — which is
// what this page is already about and what an operator otherwise reaches for `curl` to do.
// Publishing a policy and editing DNS are not here: they are text somebody composes, not a
// button, and a form that got them subtly wrong would be worse than the curl it replaced.

/**
 * Runs a write.
 *
 * `refresh` is opt-in, and the two callers below want opposite things. Revoking a device
 * must refresh, and through start() rather than the poll timer: a page that changed
 * something and kept showing the old state makes somebody click twice, and on a revoke the
 * second click is the one that does damage. Minting a token must not, because it changes
 * nothing the overview reports — the poll would fetch an identical answer and the person is
 * mid-way through copying a secret.
 *
 * The control is held still while the write runs. The page updates underneath it every few
 * seconds and would otherwise hand back an enabled button labelled as though nothing had
 * been clicked, for an action still in flight.
 */
async function act(node, run, { refresh = false } = {}) {
  const previous = node.textContent;
  node.disabled = true;
  node.textContent = "…";
  node.setAttribute("data-busy", "");
  try {
    await run();
    node.removeAttribute("data-busy");
    if (refresh) {
      // Left disabled and still saying "…". The refresh is what puts this control back, and
      // between here and there the write has happened and the button means nothing.
      restart();
    } else {
      node.disabled = false;
      node.textContent = previous;
    }
  } catch (err) {
    node.removeAttribute("data-busy");
    node.disabled = false;
    node.textContent = previous;
    // Shown against the control that failed rather than at the top of the page, because
    // by the time somebody has scrolled to a device the top is not where they are looking.
    // Marked transient so that the next update leaves it alone — an error that vanished at
    // the next poll would last about long enough to notice and not long enough to read.
    const message = el("span", { class: "error inline", "data-transient": "" }, ` ${reason(err)}`);
    node.after(message);
    setTimeout(() => message.remove(), 8000);
  }
}

/** The button that throws a device off the network. */
function revokeButton(device) {
  if (!may("network.devices.revoke") || device.state !== "active") return null;

  const button = el(
    "button",
    // Which device this is, on the button rather than only in the closure below. The node
    // outlives the render that made it, so what it was built beside is not what is on the
    // screen by the time it is clicked.
    //
    // Keyed, because the cell beside it can hold a Forget button instead. Two unkeyed
    // <button class="danger"> elements are comparable(), so the reconciler matched them by
    // position and reused this node — updating the label to "Forget" and keeping this
    // click listener, which asked to revoke a device somebody had asked to erase.
    { class: "danger", type: "button", "data-key": "revoke", "data-membership": device.membership_id },
    "Revoke",
  );
  button.addEventListener("click", () => {
    const membershipID = button.dataset.membership;
    const current = lastGood ? lastGood.devices : [];
    const named = current.find((d) => d.membership_id === membershipID) || device;
    // Confirmed, because this is not undoable: the device has to enrol again with a fresh
    // token, and its addresses go back to the pool. A one-click version of that beside a
    // device somebody is already worried about is a trap. It names the device as it is
    // called now — a confirmation naming the wrong one is worse than no confirmation.
    if (!window.confirm(`Revoke ${named.device_name}? It will lose access immediately and must enrol again.`)) {
      return;
    }
    act(
      button,
      () =>
        api(
          `/api/v1/networks/${encodeURIComponent(currentNetworkID())}` +
            `/devices/${encodeURIComponent(membershipID)}`,
          { method: "DELETE" },
        ),
      { refresh: true },
    );
  });
  return button;
}

/**
 * The organisation the network on screen belongs to.
 *
 * Read from the network list rather than from the overview, which does not carry it: the
 * list is already fetched for the picker and every row has it, so this needs no new field
 * on an endpoint polled every few seconds by every open page.
 */
function organizationOf(data, networks) {
  const network = (networks || []).find((n) => n.id === data.network.id);
  return network ? network.organization_id : null;
}

/**
 * The button that erases a device rather than removing it from a network.
 *
 * Only once a device is revoked. The two are a sequence, not alternatives: this listing
 * keeps revoked memberships precisely so somebody can confirm a device is out, and erasing
 * it is the cleanup after that confirmation. Offering both at once beside a device still
 * carrying traffic would make the more destructive one a mis-click.
 *
 * Organisation-scoped, unlike revoking, because a device can hold memberships in several
 * networks and no one of them owns it (ADR-0004) — so this removes it from all of them at
 * once, which is the thing the confirmation has to say out loud.
 */
function forgetButton(device, organizationID) {
  if (!may("organization.devices.forget")) return null;
  if (device.state === "active" || !organizationID) return null;

  const button = el(
    "button",
    { class: "danger", type: "button", "data-key": "forget", "data-device": device.device_id },
    "Forget",
  );
  button.addEventListener("click", () => {
    const deviceID = button.dataset.device;
    const current = lastGood ? lastGood.devices : [];
    const named = current.find((d) => d.device_id === deviceID) || device;
    if (
      !window.confirm(
        `Forget ${named.device_name}? This erases the device, its keys and its ` +
          `memberships in every network. It cannot be undone, and the audit trail is all ` +
          `that will be left of it.`,
      )
    ) {
      return;
    }
    act(
      button,
      () =>
        api(
          `/api/v1/organizations/${encodeURIComponent(organizationID)}` +
            `/devices/${encodeURIComponent(deviceID)}`,
          { method: "DELETE" },
        ),
      { refresh: true },
    );
  });
  return button;
}

/**
 * The policy, edited as a document (ADR-0032 §3).
 *
 * Text rather than a form. An access policy is something somebody composes, and a form that
 * reconstructed it from checkboxes would be a second grammar for the same thing — one that
 * can express less than the document does and gets the rest subtly wrong. What is stored is
 * what is reviewed.
 *
 * Nothing here decides whether a policy is valid. The control plane parses it, and asking is
 * a dry-run: the same call that shows what a device would enforce refuses a document it
 * cannot compile, with the reason. A page holding its own opinion of what a policy means
 * would be a second implementation of the thing that decides who can reach what.
 */
function renderPolicyEditor() {
  if (!may("network.acl.write")) return null;

  const box = el("textarea", {
    id: "acl-document",
    "data-key": "acl-document",
    rows: 10,
    spellcheck: "false",
  }, policyText ?? "");
  box.addEventListener("input", () => {
    // Into module state, so the next poll redraws what is being typed rather than replacing
    // it with what the network published.
    policyText = box.value;
    policyError = null;
    renderFromLastGood();
  });

  const changed = policyText !== null && policyText !== policyLive;

  const publish = el(
    "button",
    { class: "primary", type: "button", disabled: !changed },
    policyLive === null ? "Publish the first policy" : "Publish",
  );
  publish.addEventListener("click", () => {
    const document_ = policyText;
    if (!window.confirm(
      policyLive === null
        ? "Publish this? Everything it does not permit stops being reachable."
        : "Publish this policy? Every device in the network is told immediately.",
    )) {
      return;
    }
    act(publish, async () => {
      try {
        await api(`/api/v1/networks/${encodeURIComponent(currentNetworkID())}/acl`, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: document_,
        });
      } catch (err) {
        // The control plane's own words. "rule 3: names ports with protocol icmp" is the
        // difference between fixing a policy and guessing at it, and it is the one place
        // where a detailed error is the whole value.
        policyError = reason(err);
        renderFromLastGood();
        throw err;
      }
      // Both cleared so the refresh below reads them back from the control plane.
      //
      // A policy is stored parsed, so what comes back is canonical however it was typed —
      // and keeping the typed text while the live copy became canonical left the editor
      // reporting changes to a document it had just published. The same disagreement the
      // CLI's diff had, arriving from the other side.
      policyText = null;
      policyLive = null;
      policyError = null;
      policyTest = null;
    }, { refresh: true });
  });

  return el(
    "div",
    { class: "panel", "data-key": "acl-editor" },
    policyLive === null
      ? el("p", { class: "note" },
          "This network has no policy, so every device may reach every other. " +
          "Publishing one makes everything it does not permit unreachable.")
      : null,
    box,
    policyError ? el("p", { class: "error" }, policyError) : null,
    changed ? renderPolicyDiff() : el("p", { class: "note" }, "No changes."),
    publish,
  );
}

/** What publishing would change, line by line. */
function renderPolicyDiff() {
  const rows = diffLines(policyLive ?? "", policyText ?? "");
  return el(
    "div",
    { class: "result", "data-key": "acl-diff" },
    el("div", { class: "note" }, "Changes"),
    el(
      "ul",
      { class: "faults diff" },
      rows.map((row, i) =>
        el("li", { class: row.kind, "data-key": `d-${i}` }, `${row.mark} ${row.text}`),
      ),
    ),
  );
}

/**
 * A line diff, showing only what moved and the lines around it.
 *
 * The shared ends are trimmed first, so an edit to one rule is a handful of lines however
 * long the document is — and the middle is capped, because the subsequence below is O(n*m)
 * over text somebody is typing into.
 */
function diffLines(before, after) {
  const split = (s) => (s === "" ? [] : s.replace(/\n$/, "").split("\n"));
  let old = split(before);
  let next = split(after);

  const head = [];
  const tail = [];
  while (old.length && next.length && old[0] === next[0]) {
    head.push(old.shift());
    next.shift();
  }
  while (old.length && next.length && old[old.length - 1] === next[next.length - 1]) {
    tail.unshift(old.pop());
    next.pop();
  }

  const rows = [];
  // Only the last few unchanged lines before the change, and the first few after: the rest
  // is a document somebody can already see in the box above.
  for (const text of head.slice(-2)) rows.push({ mark: " ", kind: "same", text });

  if (old.length > 400 || next.length > 400) {
    rows.push({ mark: "…", kind: "same", text: `${old.length} lines replaced by ${next.length}` });
  } else {
    const common = commonLines(old, next);
    let i = 0;
    let j = 0;
    for (const line of common) {
      while (i < old.length && old[i] !== line) rows.push({ mark: "-", kind: "gone", text: old[i++] });
      while (j < next.length && next[j] !== line) rows.push({ mark: "+", kind: "new", text: next[j++] });
      rows.push({ mark: " ", kind: "same", text: line });
      i++;
      j++;
    }
    for (; i < old.length; i++) rows.push({ mark: "-", kind: "gone", text: old[i] });
    for (; j < next.length; j++) rows.push({ mark: "+", kind: "new", text: next[j] });
  }

  for (const text of tail.slice(0, 2)) rows.push({ mark: " ", kind: "same", text });
  return rows;
}

/** The longest common subsequence of two line lists. */
function commonLines(a, b) {
  const table = Array.from({ length: a.length + 1 }, () => new Int32Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      table[i][j] =
        a[i] === b[j]
          ? table[i + 1][j + 1] + 1
          : Math.max(table[i + 1][j], table[i][j + 1]);
    }
  }
  const out = [];
  for (let i = 0, j = 0; i < a.length && j < b.length; ) {
    if (a[i] === b[j]) {
      out.push(a[i]);
      i++;
      j++;
    } else if (table[i + 1][j] >= table[i][j + 1]) {
      i++;
    } else {
      j++;
    }
  }
  return out;
}

/**
 * What a device would enforce, asked of the control plane rather than worked out here.
 *
 * A policy is written in selectors and what reaches a device is a packet filter in
 * prefixes, and the step between them is where a rule that does not do what its author
 * meant goes unnoticed until somebody cannot reach something. The compile belongs to the
 * control plane — it resolves against the devices a policy applies to, excluding the
 * revoked and the addressless, and this page has no business holding a second opinion of
 * that (ADR-0023).
 */
function renderPolicyTest(devices) {
  if (!may("network.acl.write")) return null;

  const eligible = devices.filter((d) => d.state === "active");
  if (eligible.length === 0) return null;

  const picker = el(
    "select",
    { id: "acl-test-device" },
    eligible.map((d) =>
      el("option", { value: d.membership_id, "data-key": d.membership_id }, d.device_name),
    ),
  );
  if (policyTest && eligible.some((d) => d.membership_id === policyTest.membershipID)) {
    picker.value = policyTest.membershipID;
  }

  const button = el("button", { type: "button" }, "What does it enforce?");
  button.addEventListener("click", () => {
    // Read at the moment of the click. The node outlives the render that built it, so the
    // device chosen is whatever the picker says now.
    const membershipID = picker.value;
    policyTest = null;

    // The body has to be JSON to carry a document, so text that is not JSON cannot be sent
    // at all. Said here rather than as a failed request, because this is the one class of
    // mistake the page can name without asking.
    let proposed;
    if (policyText !== null && policyText !== policyLive) {
      try {
        proposed = JSON.parse(policyText);
      } catch (err) {
        policyError = `That is not JSON yet: ${err.message}`;
        renderFromLastGood();
        return;
      }
    }

    act(button, async () => {
      const body = await api(
        `/api/v1/networks/${encodeURIComponent(currentNetworkID())}/acl/test`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          // The document being edited, not the one in force. Checking what is live is
        // available by not having changed anything; checking what you are about to publish
        // is the question worth asking.
        // The document being edited, not the one in force. Checking what is live is
        // available by not having changed anything; checking what you are about to publish
        // is the question worth asking.
        body: JSON.stringify(
          proposed === undefined
            ? { device: membershipID }
            : { device: membershipID, document: proposed },
        ),
        },
      );
      policyError = null;
      policyTest = {
        membershipID,
        device: body.device,
        defaultDeny: body.default_deny,
        inbound: (body.filter && body.filter.inbound) || [],
        outbound: (body.filter && body.filter.outbound) || [],
      };
      renderFromLastGood();
    });
  });

  return el(
    "div",
    { class: "row", "data-key": "acl-test" },
    el("label", { class: "note", for: "acl-test-device" }, "Compile it for"),
    picker,
    button,
    policyTest ? renderPolicyResult() : null,
  );
}

/**
 * The policy, and the two things somebody does with it.
 *
 * One panel because it is one job: the document is edited and then checked against a
 * device, and splitting them put the same heading on the page twice with a card boundary
 * between two halves of the same sentence.
 */
function renderPolicy(devices) {
  const editor = renderPolicyEditor();
  if (editor === null) {
    return el("div", { class: "panel note", "data-key": "acl" },
      "You may not change this network's policy.");
  }
  // The dry-run inside the same panel, under a rule: it is the last step of publishing,
  // not a separate feature.
  const test = renderPolicyTest(devices);
  if (test !== null) editor.append(test);
  return editor;
}

/** The compiled filter, in the prefixes a device enforces rather than the tags somebody wrote. */
function renderPolicyResult() {
  const direction = (label, rules) =>
    el(
      "div",
      { "data-key": label },
      el("div", { class: "note" }, label),
      rules.length === 0
        ? el("div", { class: "addr" }, "nothing")
        : el(
            "ul",
            { class: "faults" },
            rules.map((r, i) =>
              el(
                "li",
                { "data-key": `${label}-${i}` },
                `${r.allow ? "allow" : "deny"} ${r.protocol || "any"} ` +
                  `${(r.src_prefixes || []).join(",") || "anywhere"} \u2192 ` +
                  `${(r.dst_prefixes || []).join(",") || "anywhere"}` +
                  ((r.ports || []).length ? ` ports ${r.ports.join(",")}` : ""),
              ),
            ),
          ),
    );

  return el(
    "div",
    { class: "result", "data-key": "acl-result" },
    el("div", {}, el("strong", {}, policyTest.device)),
    el(
      "div",
      { class: "note" },
      policyTest.defaultDeny
        ? "Everything not listed is refused."
        : "Everything is permitted; these rules add nothing.",
    ),
    direction("inbound", policyTest.inbound),
    direction("outbound", policyTest.outbound),
  );
}

/** The panel that mints an enrolment token, and shows it exactly once. */
function renderAddDevice() {
  if (!may("network.enrollment_tokens.write")) return null;

  const button = el("button", { class: "primary", type: "button" }, "Create an enrolment token");
  button.addEventListener("click", () => {
    mintedToken = null;
    act(button, async () => {
      const body = await api(
        `/api/v1/networks/${encodeURIComponent(currentNetworkID())}/enrollment-tokens`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          // One device, one hour. Deliberately the narrowest thing that is useful: a
          // token minted from a page somebody left open should not outlive the afternoon,
          // and anybody who needs a wider one is already using the API.
          body: JSON.stringify({ max_uses: 1, expires_in_seconds: 3600 }),
        },
      );
      // Into module state, not only into the DOM, so that every render from here draws it.
      mintedToken = body.token;
      // Drawn now rather than at the next poll: this response is the only place the token
      // exists. The page keeps polling underneath it — the selection somebody is making in
      // order to copy it survives an update, which is the whole reason updates happen in
      // place (see "keeping the page still").
      renderFromLastGood();
    });
  });

  return el(
    "div",
    { class: mintedToken ? "panel" : "panel slim", "data-key": "add-device" },
    button,
    mintedToken ? renderMintedToken() : null,
  );
}

/** The one showing of a token, kept across re-renders until it is dismissed. */
function renderMintedToken() {
  const done = el("button", { class: "quiet", type: "button" }, "Done");
  done.addEventListener("click", () => {
    mintedToken = null;
    renderFromLastGood();
  });

  return el(
    "div",
    {},
    el(
      "p",
      { class: "note" },
      "Copy this now — it is not shown again, and it is good for one device for an hour.",
    ),
    el("code", { class: "token" }, mintedToken),
    el(
      "p",
      { class: "note" },
      "On the device: ",
      el("span", { class: "mono" }, `meshp up --token ${mintedToken}`),
    ),
    done,
  );
}

/**
 * Redraws from the last good poll, without waiting for the next one.
 *
 * For state that is this page's own rather than the control plane's — whether a minted token
 * is on screen — where asking the server again would answer a question it was never asked.
 */
function renderFromLastGood() {
  if (lastGood) renderOverview(lastGood, lastNetworks, lastHistory);
}

function renderOverview(data, networks, history) {

  // Devices with something wrong first. A list sorted by name buries the one device the
  // page exists to surface somewhere in the middle of forty that are fine.
  const devices = [...data.devices].sort((a, b) => {
    const byFault = ((b.faults || []).length > 0) - ((a.faults || []).length > 0);
    if (byFault) return byFault;
    return a.device_name.localeCompare(b.device_name);
  });

  // Keyed section by section, so that a panel which comes and goes — the one that mints a
  // token exists only for somebody who may mint one — moves nothing else on the page.
  // Ordered by what somebody came for. The verdict answers the question the page exists to
  // answer; the devices are what they look at next; the things that change the network come
  // after the things that describe it, and the trail is last because it is history.
  //
  // A heading owns what follows it. "Devices" used to sit above three panels that were not
  // devices, with the table below them — which is the sort of thing that reads as a page
  // nobody laid out.
  update(
    renderNetworkBar(data, networks),
    renderVerdict(data, data.fault_count || 0),

    el("h2", { "data-key": "devices-heading" }, "Devices"),
    el(
      "div",
      { class: "panel", "data-key": "devices" },
      renderDevices(devices, organizationOf(data, networks)),
      data.devices_truncated
        ? el(
            "p",
            { class: "note" },
            "This network holds more devices than are shown. The list above is cut, not short.",
          )
        : null,
    ),
    renderAddDevice(),

    el("h2", { "data-key": "carried-heading" }, "What is carried, and by what"),
    data.route_groups.length
      ? el("div", { "data-key": "groups" }, data.route_groups.map(renderGroup))
      : el("div", { class: "panel note", "data-key": "groups" }, "This network has no route groups."),

    el("h2", { "data-key": "policy-heading" }, "Access policy"),
    renderPolicy(devices),

    el("h2", { "data-key": "history-heading" }, "What has happened"),
    renderHistory(history),
  );
}

// What an action is, in words. Unknown codes render as themselves rather than being hidden
// or guessed at: a new one is a line somebody should see, not a line that quietly vanishes.
const ACTIONS = {
  "device.enrolled": "joined the network",
  "device.revoked": "was removed from the network",
  "policy.published": "published a policy",
  "route.switched": "moved to another candidate",
  "role.granted": "was given a role",
  "role.revoked": "had a role taken away",
  "api_token.minted": "created an API token",
  "api_token.revoked": "revoked an API token",
};

/** The audit trail, newest first. */
function renderHistory(history) {
  if (history === null) {
    return el("div", { class: "panel note", "data-key": "history" }, "The history could not be read just now.");
  }
  if (!history.length) {
    return el(
      "div",
      { class: "panel note", "data-key": "history" },
      "Nothing has been recorded for this network yet.",
    );
  }

  const rows = history.map((event) => {
    const metadata = event.metadata || {};
    const bits = [];
    // The agent's own account of why it moved, which is the whole reason this record
    // exists — the schema describes it as what answers "why did my outbound IP change?".
    if (metadata.reason) bits.push(metadata.reason);
    if (metadata.switched_from) bits.push("was on another candidate");

    return el(
      "li",
      { class: "event", "data-key": event.id },
      el("span", { class: "when mono" }, new Date(event.at).toLocaleString()),
      el("span", { class: "who" }, event.actor_label || event.actor_kind),
      el("span", {}, ACTIONS[event.action] || event.action),
      bits.length ? el("span", { class: "why" }, bits.join(" · ")) : null,
    );
  });

  return el(
    "div",
    { class: "panel", "data-key": "history" },
    el("ul", { class: "events" }, rows),
    el(
      "p",
      { class: "note" },
      "The ten most recent. The whole trail is at /api/v1/networks/{id}/audit, newest first.",
    ),
  );
}

function renderNetworkBar(data, networks) {
  const select = el("select", { id: "network" });
  for (const network of networks) {
    const option = el(
      "option",
      { value: network.id, "data-key": network.id },
      `${network.organization_slug} / ${network.slug}`,
    );
    if (network.id === data.network.id) option.selected = true;
    select.append(option);
  }
  select.addEventListener("change", () => {
    location.hash = `#/networks/${select.value}`;
  });

  return el(
    "div",
    { class: "panel slim picker", "data-key": "picker" },
    el("label", { for: "network" }, "Network"),
    select,
    el("span", { class: "note" }, `state version ${data.network.state_version}`),
  );
}

// --- freshness ------------------------------------------------------------------------

/**
 * Says how old what is on screen is, and says it in the page rather than only in a
 * console. Recomputed on a timer of its own so the age keeps counting up while a poll is
 * failing — a number frozen at "2s ago" is exactly the lie this is here to prevent.
 */
function renderFreshness(problem) {
  if (freshnessTimer) clearInterval(freshnessTimer);
  const paint = () => {
    if (!lastGoodAt) {
      freshnessEl.textContent = problem || "";
      freshnessEl.classList.toggle("stale", Boolean(problem));
      return;
    }
    const age = Math.round((Date.now() - lastGoodAt) / 1000);
    const ago = age < 2 ? "just now" : `${age}s ago`;
    freshnessEl.textContent = problem ? `${problem} — last update ${ago}` : `updated ${ago}`;
    freshnessEl.classList.toggle("stale", Boolean(problem));
  };
  paint();
  freshnessTimer = setInterval(paint, 1000);
}

// --- sign in --------------------------------------------------------------------------

function renderSignIn(message, options = {}) {
  const email = el("input", {
    type: "email",
    id: "email",
    name: "email",
    autocomplete: "username",
    placeholder: "you@example.com",
    required: "required",
  });
  const password = el("input", {
    type: "password",
    id: "password",
    name: "password",
    autocomplete: "current-password",
    placeholder: "password",
    required: "required",
  });
  // Asked for only after the server says the address is ambiguous. Almost every deployment
  // has one organisation, so asking everybody up front would be a field almost nobody needs
  // and everybody has to read.
  const organization = el("input", {
    type: "text",
    id: "organization",
    name: "organization",
    autocomplete: "organization",
    placeholder: "organisation",
  });
  const error = el("p", { class: "error" }, message || "");

  const fields = [
    el("label", { for: "email" }, "Email"),
    email,
    el("label", { for: "password" }, "Password"),
    password,
  ];
  if (options.needsOrganization) {
    fields.push(el("label", { for: "organization" }, "Organisation"), organization);
  }

  const form = el(
    "form",
    { class: "signin" },
    ...fields,
    el("button", { class: "primary", type: "submit" }, "Sign in"),
  );
  form.addEventListener("submit", async (event) => {
    // Always, and first. The CSP sets form-action 'none' so a native submit cannot leave
    // this origin at all, but a native submit would also put the password in a URL if the
    // form ever gained a GET method by accident.
    event.preventDefault();
    error.textContent = "";
    try {
      await api("/api/v1/ui/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: email.value,
          password: password.value,
          organization: organization.value || undefined,
        }),
      });
      password.value = "";
      start();
    } catch (err) {
      if (err.code === "ambiguous_sign_in") {
        renderSignIn(err.message, { needsOrganization: true });
        return;
      }
      error.textContent = err.message;
      password.value = "";
      password.focus();
    }
  });

  show(
    el(
      "div",
      { class: "panel" },
      el("h1", {}, "Sign in"),
      el(
        "p",
        { class: "note" },
        "Sign in with your own account. What you can see and change here is what your " +
          "role allows.",
      ),
      form,
      error,
    ),
  );
  signoutEl.hidden = true;
  email.focus();
}

// --- the loop -------------------------------------------------------------------------

function currentNetworkID() {
  const match = location.hash.match(/^#\/networks\/([0-9a-fA-F-]{36})$/);
  return match ? match[1] : null;
}

function stopPolling() {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
}

/**
 * The audit trail is read separately from the overview, and that is not the mistake
 * ADR-0022 §1 rules out.
 *
 * That rule is about current state: devices from one instant beside route groups from
 * another render a network that never existed. History cannot do that. Events are appended
 * and never change, so a page of them read a moment later than the state beside it says the
 * same thing it would have said a moment earlier — the two panels do not describe one
 * instant and are not presented as though they do.
 *
 * Failing is not fatal. The question this page exists to answer is in the overview; the
 * history is context, and losing it should not blank a screen somebody is reading during an
 * outage.
 */
async function fetchHistory(networkID) {
  try {
    const body = await api(`/api/v1/networks/${encodeURIComponent(networkID)}/audit?limit=10`);
    return body.events || [];
  } catch {
    return null;
  }
}

/**
 * Reads what this person may do here.
 *
 * Failing is not fatal and leaves the set empty, which renders a page with no controls
 * rather than no page. Somebody who can see that a device is unreachable and cannot click
 * anything is worse off than before this slice; somebody staring at an error where the
 * network used to be is worse off than that.
 */
/**
 * Reads the policy in force, once for the network being shown.
 *
 * A failure leaves the editor empty rather than guessing: an editor pre-filled with a
 * document the control plane did not send is one somebody could publish believing it was
 * already live.
 */
async function fetchPolicy(networkID) {
  if (!may("network.acl.write")) return;
  try {
    const body = await api(`/api/v1/networks/${encodeURIComponent(networkID)}/acl`);
    policyLive = JSON.stringify(body.document, null, 2) + "\n";
  } catch (err) {
    // A network with no policy is unfiltered, which is a state rather than a failure.
    policyLive = err.status === 404 ? null : policyLive;
  }
  if (policyText === null) policyText = policyLive ?? starterPolicy;
}

/** What an editor offers a network that has none: deny nothing, written out. */
const starterPolicy = `{
  "version": 1,
  "comment": "Every device may reach every other. Narrow this.",
  "rules": [
    { "src": ["*"], "dst": ["*"], "protocol": "any" }
  ]
}
`;

async function fetchPermissions(networkID) {
  try {
    const body = await api(`/api/v1/me/permissions?network=${encodeURIComponent(networkID)}`);
    permissions = new Set(body.permissions || []);
    unlimited = Boolean(body.unlimited);
  } catch {
    permissions = new Set();
    unlimited = false;
  }
}

async function poll(networkID, networks) {
  try {
    const data = await api(`/api/v1/networks/${encodeURIComponent(networkID)}/overview`);
    lastGood = data;
    lastGoodAt = Date.now();
    lastNetworks = networks;
    lastHistory = await fetchHistory(networkID);
    renderOverview(data, networks, lastHistory);
    renderFreshness(null);
    // The server decides how often it is asked, so a deployment under load can slow its
    // pages down without shipping a new one.
    const wait = Math.max(1, Number(data.poll_after_seconds) || 5) * 1000;
    pollTimer = setTimeout(() => poll(networkID, networks), wait);
  } catch (err) {
    if (err.status === 401) {
      stopPolling();
      renderSignIn("That session has expired. Sign in again.");
      return;
    }
    if (err.status === 404) {
      stopPolling();
      lastGood = null;
      lastGoodAt = null;
      renderFreshness("no such network");
      show(
        el(
          "div",
          { class: "panel" },
          el("h1", {}, "No such network"),
          el("p", { class: "note" }, "It may have been deleted, or the link may be wrong."),
          el("p", {}, el("a", { href: "#/" }, "Pick another network")),
        ),
      );
      return;
    }
    // Anything else: keep what is on screen, say plainly that it is not current, and
    // keep trying. Blanking the page on a transient failure throws away the last thing
    // somebody was reading at the moment they most want to look at it.
    renderFreshness(reason(err));
    if (!lastGood) {
      show(el("div", { class: "panel error" }, `Could not read this network: ${reason(err)}`));
    }
    pollTimer = setTimeout(() => poll(networkID, networks), 5000);
  }
}

function renderPicker(networks) {
  show(
    el(
      "div",
      { class: "panel" },
      el("h1", {}, "Pick a network"),
      networks.length
        ? el(
            "ul",
            {},
            networks.map((network) =>
              el(
                "li",
                {},
                el(
                  "a",
                  { href: `#/networks/${network.id}` },
                  `${network.organization_slug} / ${network.slug}`,
                ),
                el(
                  "span",
                  { class: "note" },
                  ` — ${network.active_device_count} active device${network.active_device_count === 1 ? "" : "s"}`,
                ),
              ),
            ),
          )
        : el(
            "p",
            { class: "note" },
            "This control plane holds no networks yet. Create one with the API or the CLI.",
          ),
    ),
  );
}

async function start() {
  stopPolling();
  let networks;
  try {
    const body = await api("/api/v1/networks");
    networks = body.networks;
  } catch (err) {
    if (err.status === 401) {
      renderSignIn(null);
      return;
    }
    renderFreshness(reason(err));
    show(el("div", { class: "panel error" }, `Could not list networks: ${reason(err)}`));
    return;
  }

  signoutEl.hidden = false;
  const networkID = currentNetworkID();
  if (!networkID) {
    lastGood = null;
    lastGoodAt = null;
    renderFreshness(null);
    // One network and no choice to make: go straight to it rather than asking somebody
    // to pick from a list of one.
    if (networks.length === 1) {
      location.hash = `#/networks/${networks[0].id}`;
      return;
    }
    renderPicker(networks);
    return;
  }
  // Before the first render, so a control is never absent-then-present on a page somebody
  // is already reading — and never present-then-absent, which would be worse.
  await fetchPermissions(networkID);
  if (networkID !== shownFor) {
    // A token minted for one network must not still be on screen while another is shown,
    // and neither must a policy: an editor holding one network's document while another is
    // named above it is one publish away from the wrong network.
    mintedToken = null;
    policyText = null;
    policyLive = null;
    policyError = null;
    policyTest = null;
    shownFor = networkID;
  }
  // Once per network rather than per poll, like the permissions above: a policy changes
  // rarely, and re-reading it every few seconds would overwrite what somebody is typing.
  await fetchPolicy(networkID);
  poll(networkID, networks);
}

/**
 * Reloads after a write.
 *
 * Goes through start() rather than poking the poll timer, because a write can change what
 * comes next in more ways than one: revoking the last device changes the verdict, and a
 * person whose role was changed in another tab should find that out here rather than by
 * clicking something that fails.
 */
function restart() {
  stopPolling();
  start();
}

/**
 * Wires the page up and starts it. Called by main.js, which is what index.html loads.
 *
 * Separated so that importing this file does nothing. It used to attach a listener and
 * start polling at import, which meant no test could reach a renderer without a document
 * that already had the page's elements in it and a control plane to answer the first poll
 * — and so the only thing checking that these renderers build what the reconciler needs
 * was a person following docs/testing/the-page.md.
 */
export function bootstrap() {
  signoutEl.addEventListener("click", async () => {
    stopPolling();
    try {
      await api("/api/v1/ui/session", { method: "DELETE" });
    } catch {
      // Logging out of a session the server has already forgotten is still logging out.
    }
    lastGood = null;
    lastGoodAt = null;
    // Forgotten explicitly. A page that kept the last person's permissions in memory would
    // render their controls for whoever signs in next, for as long as it took the next
    // fetch to come back.
    permissions = new Set();
    unlimited = false;
    mintedToken = null;
    shownFor = null;
    policyTest = null;
    policyText = null;
    policyLive = null;
    policyError = null;
    renderFreshness(null);
    renderSignIn("Signed out.");
  });

  window.addEventListener("hashchange", start);
  start();
}

// Reached only by web/dom.test.js and web/render.test.js. Exported rather than made public
// in spirit: these are the renderers whose output the reconciler depends on, and the keys
// they carry are the difference between a button that means what it says and one that
// inherited somebody else's click handler (#218).
export {
  renderDevices,
  revokeButton,
  forgetButton,
  organizationOf,
  may,
  fetchPermissions,
  renderPolicyTest,
  renderPolicyEditor,
  diffLines,
};
