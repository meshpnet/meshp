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

/** Last successful overview, kept so a failed poll can keep showing it — marked stale. */
let lastGood = null;
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

function show(...nodes) {
  view.replaceChildren(...nodes);
}

// --- what counts as broken ------------------------------------------------------------

/**
 * Whether this candidate could carry anything at all.
 *
 * Deliberately not a function of `connected`. That is the control session, and an agent
 * keeps forwarding from the state it last applied when the control plane is unreachable
 * (ADR-0008) — so an advertiser whose session has dropped may well still be carrying, and
 * calling the group broken on that basis would raise an alarm for a control-plane outage
 * rather than a data-plane one. Disconnection is shown; it is not a fault by itself.
 *
 * `unknown` health is not treated as broken either, for the opposite reason: nobody has
 * reported on it yet, which is not the same as knowing it is down. It is called out as
 * unproven where it appears.
 */
function viable(advertiser) {
  if (advertiser.admin_state !== "enabled") return false;
  return advertiser.health !== "unhealthy" && advertiser.health !== "offline";
}

/** What is wrong with a route group, in words. Empty means nothing is. */
function groupFaults(group) {
  const faults = [];
  if (!group.advertisers.length) {
    faults.push("nothing is offering to carry this");
    return faults;
  }
  if (!group.advertisers.some(viable)) {
    faults.push("no candidate can carry this: every advertiser is disabled, draining or unhealthy");
  }
  return faults;
}

/**
 * How long a control session must have been up before a tunnel with no handshakes counts
 * as broken rather than as new.
 *
 * A device reports its data plane the moment it applies state, and at that point there
 * have been no handshakes because there has not been time for any. Without this, every
 * join would flash "has never carried anything" for as long as it took to be wrong.
 */
const TUNNEL_GRACE_SECONDS = 120;

/** What is wrong with a device, in words. `asOf` is the server's clock, not this one's. */
function deviceFaults(device, asOf) {
  const faults = [];
  if (device.state !== "active") return faults;

  if (device.unapplied_components && device.unapplied_components.length) {
    faults.push(`could not apply: ${device.unapplied_components.join(", ")}`);
  }
  if (device.last_error) {
    faults.push(device.last_error);
  }
  if (!device.connected && !device.last_ack_at) {
    // Enrolled and never heard from. Easy to miss in a list of names, and it is usually
    // an installation that did not finish rather than a device that has gone away.
    faults.push("has never applied any configuration");
  }
  // The one thing a path report is allowed to call a fault. A device can apply every
  // version it is sent and pass no traffic at all, and until it reported its peers nothing
  // could tell the difference (#117).
  //
  // "Never handshaked", not "handshaked a while ago". WireGuard renews a handshake when
  // traffic flows, so a quiet peer looks stale while being perfectly healthy — but a peer
  // that has never completed one has never carried a packet, and that is unambiguous.
  if (device.tunnel && device.tunnel.peers > 0 && device.tunnel.handshaked === 0 && settled(device, asOf)) {
    faults.push("tunnel has never carried anything: no peer has completed a handshake");
  }
  return faults;
}

/**
 * Whether this device has been connected long enough for "no handshakes" to mean anything.
 *
 * Both timestamps come from the server, so this survives a browser whose clock is wrong —
 * which is the machine somebody is reading this on, and the one whose clock nobody checks.
 */
function settled(device, asOf) {
  if (!device.connected_since || !asOf) return false;
  const up = (Date.parse(asOf) - Date.parse(device.connected_since)) / 1000;
  return Number.isFinite(up) && up > TUNNEL_GRACE_SECONDS;
}

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
  const faults = groupFaults(group);

  const carriers = group.advertisers.map((advertiser) => {
    const health = advertiser.health || "unknown";
    const bits = [`priority ${advertiser.priority}`];
    if (advertiser.weight !== 1) bits.push(`weight ${advertiser.weight}`);
    bits.push(health === "unknown" ? "never health checked" : health);
    if (advertiser.admin_state !== "enabled") bits.push(advertiser.admin_state);
    // Named as a control-plane fact, not as an outage, because it is not one.
    if (!advertiser.connected) bits.push("control session down");
    const where = [advertiser.city, advertiser.region].filter(Boolean).join(", ");
    if (where) bits.push(where);

    return el(
      "li",
      { class: `carrier ${viable(advertiser) ? "" : "not-viable"}` },
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
        faults.length ? el("div", { class: "nobody" }, faults.join("; ")) : null,
        carriers.length
          ? el("ul", { class: "carriers" }, carriers)
          : el("div", { class: "note" }, "no advertisers"),
      ),
    ),
  );
}

function renderDevices(devices, asOf) {
  const rows = devices.map((device) => {
    const faults = deviceFaults(device, asOf);
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
              faults.map((fault) => el("li", {}, fault)),
            )
          : el("span", { class: "note" }, "—"),
      ),
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
      ),
    ),
    el("tbody", {}, rows),
  );
  return el("div", { class: "scroll" }, table);
}

function renderOverview(data, networks) {
  const groupFaultCount = data.route_groups.reduce((n, g) => n + groupFaults(g).length, 0);
  const deviceFaultCount = data.devices.reduce((n, d) => n + deviceFaults(d, data.as_of).length, 0);

  // Devices with something wrong first. A list sorted by name buries the one device the
  // page exists to surface somewhere in the middle of forty that are fine.
  const devices = [...data.devices].sort((a, b) => {
    const byFault = (deviceFaults(b, data.as_of).length > 0) - (deviceFaults(a, data.as_of).length > 0);
    if (byFault) return byFault;
    return a.device_name.localeCompare(b.device_name);
  });

  show(
    renderNetworkBar(data, networks),
    renderVerdict(data, groupFaultCount + deviceFaultCount),
    el("h2", {}, "What is carried, and by what"),
    data.route_groups.length
      ? el("div", {}, data.route_groups.map(renderGroup))
      : el("div", { class: "panel note" }, "This network has no route groups."),
    el("h2", {}, "Devices"),
    el(
      "div",
      { class: "panel" },
      renderDevices(devices, data.as_of),
      data.devices_truncated
        ? el(
            "p",
            { class: "note" },
            "This network holds more devices than are shown. The list above is cut, not short.",
          )
        : null,
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

function renderSignIn(message) {
  const input = el("input", {
    type: "password",
    id: "token",
    autocomplete: "current-password",
    placeholder: "administrative token",
  });
  const error = el("p", { class: "error" }, message || "");

  const form = el(
    "form",
    { class: "signin" },
    input,
    el("button", { class: "primary", type: "submit" }, "Sign in"),
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.textContent = "";
    try {
      await api("/api/v1/ui/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: input.value }),
      });
      input.value = "";
      start();
    } catch (err) {
      error.textContent = err.message;
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
        "The administrative token is exchanged once for a session that may read and may " +
          "not write. It is not stored in this page.",
      ),
      form,
      error,
    ),
  );
  signoutEl.hidden = true;
  input.focus();
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

async function poll(networkID, networks) {
  try {
    const data = await api(`/api/v1/networks/${encodeURIComponent(networkID)}/overview`);
    lastGood = data;
    lastGoodAt = Date.now();
    renderOverview(data, networks);
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
  poll(networkID, networks);
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
  renderFreshness(null);
  renderSignIn("Signed out.");
});

window.addEventListener("hashchange", start);
start();
