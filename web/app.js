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
 * A token this page has just minted, held here rather than in the DOM.
 *
 * The view is replaced wholesale by every poll, and the control plane stores only a hash, so
 * a secret drawn straight into the page would be unrecoverable within a few seconds of
 * existing — and somebody would click again, minting another credential nobody can use.
 */
let mintedToken = null;
/** Which network that token was minted for, so moving away clears it. */
let shownFor = null;

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
 * Replaces the view.
 *
 * Nullish children are dropped, the same way el() drops them — and for a reason that only
 * appeared once the page had controls that are absent for some people. `replaceChildren`
 * stringifies what it is given, so a panel that renders as null for somebody without the
 * permission for it put the word "null" on their screen.
 */
function show(...nodes) {
  view.replaceChildren(...nodes.filter((node) => node !== null && node !== undefined && node !== false));
}

// --- what counts as broken ------------------------------------------------------------
//
// Nothing here decides that. The control plane does, and sends `faults` on every device and
// every route group (ADR-0023): there are two consumers of that endpoint and rules kept
// here could only ever be a second opinion that drifts from the commercial layer's. Any
// rule that reappears in this file is a bug.

/** How a device's data plane reads, in words. */
function tunnelSummary(device) {
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
    { class: `panel verdict ${faultCount ? "problems" : ""}` },
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
      { class: `carrier ${advertiser.viable ? "" : "not-viable"}` },
      dot(HEALTH_CLASS[health] || "unknown", health),
      el("span", { class: "who" }, advertiser.device_name),
      el("span", { class: "why" }, bits.join(" · ")),
    );
  });

  return el(
    "div",
    { class: "panel" },
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
          group.prefixes.map((prefix) => el("li", {}, prefix)),
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

function renderDevices(devices) {
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
      { class: faults.length ? "attention" : "" },
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
              faults.map((fault) => el("li", {}, fault.message)),
            )
          : el("span", { class: "note" }, "—"),
      ),
      // Empty for somebody who may not act, rather than absent: a column that appears and
      // disappears between people makes two screenshots of the same page look like two
      // different products.
      el("td", { class: "actions" }, revokeButton(device)),
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
 * must refresh: a page that changed something and kept showing the old state makes somebody
 * click twice, and on a revoke the second click is the one that does damage. Minting a token
 * must not: the poll re-renders this whole view every few seconds, so anything drawn here
 * and not held in state is gone within one tick — which for a secret shown exactly once
 * means a person clicking again and leaking another credential nobody can use.
 */
async function act(node, run, { refresh = false } = {}) {
  const previous = node.textContent;
  node.disabled = true;
  node.textContent = "…";
  try {
    await run();
    if (refresh) restart();
    else {
      node.disabled = false;
      node.textContent = previous;
    }
  } catch (err) {
    node.disabled = false;
    node.textContent = previous;
    // Shown against the control that failed rather than at the top of the page, because
    // by the time somebody has scrolled to a device the top is not where they are looking.
    const message = el("span", { class: "error inline" }, ` ${reason(err)}`);
    node.after(message);
    setTimeout(() => message.remove(), 8000);
  }
}

/** The button that throws a device off the network. */
function revokeButton(device) {
  if (!may("network.devices.revoke") || device.state !== "active") return null;

  const button = el("button", { class: "danger", type: "button" }, "Revoke");
  button.addEventListener("click", () => {
    // Confirmed, because this is not undoable: the device has to enrol again with a fresh
    // token, and its addresses go back to the pool. A one-click version of that beside a
    // device somebody is already worried about is a trap.
    if (!window.confirm(`Revoke ${device.device_name}? It will lose access immediately and must enrol again.`)) {
      return;
    }
    act(
      button,
      () =>
        api(
          `/api/v1/networks/${encodeURIComponent(currentNetworkID())}` +
            `/devices/${encodeURIComponent(device.membership_id)}`,
          { method: "DELETE" },
        ),
      { refresh: true },
    );
  });
  return button;
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
      // Into module state, not into the DOM. This view is replaced wholesale by the next
      // poll, and the control plane stores only a hash — so a token drawn straight into
      // the page would be unrecoverable within a few seconds of existing.
      mintedToken = body.token;
      // Polling stops while it is on screen. Every poll replaces this view wholesale, which
      // would wipe a half-made text selection — and the whole point of showing a secret once
      // is that somebody selects it and copies it. A dashboard that refreshes out from under
      // the one thing it asked you to copy is worse than one that pauses and says so.
      stopPolling();
      renderFromLastGood();
    });
  });

  return el(
    "div",
    { class: "panel" },
    el("h3", {}, "Add a device"),
    button,
    mintedToken ? renderMintedToken() : null,
  );
}

/** The one showing of a token, kept across re-renders until it is dismissed. */
function renderMintedToken() {
  const done = el("button", { class: "quiet", type: "button" }, "Done");
  done.addEventListener("click", () => {
    mintedToken = null;
    // Which also starts the page updating again.
    restart();
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
    // Said rather than left to be noticed. The page's own rule is that it never lies about
    // its freshness, and it is deliberately not updating right now.
    el("p", { class: "note" }, "This page has paused while the token is shown."),
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

  show(
    renderNetworkBar(data, networks),
    renderVerdict(data, data.fault_count || 0),
    el("h2", {}, "What is carried, and by what"),
    data.route_groups.length
      ? el("div", {}, data.route_groups.map(renderGroup))
      : el("div", { class: "panel note" }, "This network has no route groups."),
    el("h2", {}, "Devices"),
    renderAddDevice(),
    el(
      "div",
      { class: "panel" },
      renderDevices(devices),
      data.devices_truncated
        ? el(
            "p",
            { class: "note" },
            "This network holds more devices than are shown. The list above is cut, not short.",
          )
        : null,
    ),
    el("h2", {}, "What has happened"),
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
    return el("div", { class: "panel note" }, "The history could not be read just now.");
  }
  if (!history.length) {
    return el("div", { class: "panel note" }, "Nothing has been recorded for this network yet.");
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
      { class: "event" },
      el("span", { class: "when mono" }, new Date(event.at).toLocaleString()),
      el("span", { class: "who" }, event.actor_label || event.actor_kind),
      el("span", {}, ACTIONS[event.action] || event.action),
      bits.length ? el("span", { class: "why" }, bits.join(" · ")) : null,
    );
  });

  return el(
    "div",
    { class: "panel" },
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
      { value: network.id },
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
    { class: "panel picker" },
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
    // A token minted for one network must not still be on screen while another is shown.
    mintedToken = null;
    shownFor = networkID;
  }
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
  // render their controls for whoever signs in next, for as long as it took the next fetch
  // to come back.
  permissions = new Set();
  unlimited = false;
  mintedToken = null;
  shownFor = null;
  renderFreshness(null);
  renderSignIn("Signed out.");
});

window.addEventListener("hashchange", start);
start();
