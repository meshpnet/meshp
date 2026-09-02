# What the page does while somebody is using it

The page polls, so it redraws itself every few seconds under whoever is reading it. Nothing
in CI runs it: `web/app.js` is the one file in this repository that executes in a browser and
the one file no job executes at all. What holds it up is Go tests asserting the control plane
serves it (`internal/api/page_test.go`) and a person opening it.

This is that person's list. **Run it before merging anything that touches `web/app.js`.**

## Bringing it up

```
python3 web/testdata/fixture.py web
open http://localhost:8731/#/networks/11111111-2222-3333-4444-555555555555
```

That is a canned control plane, not a real one — four devices, one route group, three audit
events, every permission granted, and a poll every second so that waiting for one is not
waiting. `POST /fixture` replaces the state its answers are built from:

```
curl -sX POST localhost:8731/fixture -d '{"fault":"delta"}'          # delta sorts to the top
curl -sX POST localhost:8731/fixture -d '{"rename":{"charlie":"x"}}' # a device is renamed
curl -sX POST localhost:8731/fixture -d '{"fault":null,"rename":{},"revoked":[]}'
```

Against a real control plane everything below still applies except the two checks that need a
device to change while you watch.

## The checks

Each one is a thing the page got wrong before #146, so each one is worth repeating.

1. **A selection survives a poll.** Create an enrolment token, select the token text, and
   wait ten seconds without touching anything. The selection is still there, the header still
   counts up, and the page has not paused. *Before #146 the page had to stop polling to make
   this true, and said so on screen.*

2. **Focus survives a poll.** Tab to a Revoke button and wait ten seconds. It still has the
   focus ring. Then `POST /fixture` a fault onto a device below it, so the table reorders
   under the focused row: the ring is still on the same button.

3. **A row that moves is the row that moved.** With the table sorted by name, make one device
   develop a fault. It moves to the top, gains its fault text and the `attention` class, and
   every other row keeps the device it had — no row is rewritten to hold a different device.

4. **A rename lands where it is.** Rename a device and watch its row: the name changes, the
   row does not blink.

5. **A control with a write in flight is left alone.** `POST /fixture` with
   `{"slow_mint":4}`, then click *Create an enrolment token* and let the polls land while it
   waits. The button still says `…` and is still disabled the whole way through. *A page that
   hands the button back mid-write is one double-click away from a second credential nobody
   can use.*

6. **A failed write says so for long enough to read.** `POST /fixture` with
   `{"fail_mint":true}`, then click *Create an enrolment token*. The error appears beside the
   button, survives the polls that keep landing behind it, and takes itself off about eight
   seconds later. The poll has to keep succeeding for this to mean anything, which is why the
   fixture fails the write rather than going offline.

7. **The picker names the network on screen.** With more than one network, switch between
   them and check the dropdown follows, in both directions, including via the browser's back
   button.

8. **A button that changes identity changes handler.** With every device active, `POST
   /fixture` with `{"revoked":["bravo"]}` and watch bravo's row: *Revoke* becomes *Forget*
   without the row blinking. Now click it. The confirmation must say **Forget bravo**, not
   *Revoke bravo*. *Two `<button class="danger">` elements are `comparable()`, so before both
   were keyed the reconciler matched them by position and reused the node — relabelling it
   while keeping the old click listener. The page offered to erase a device and revoked it
   instead, which is the more alarming direction for that mistake to go in.*

## What a machine checks now, and what it does not

`web/dom.test.js` runs in CI (`the page` job) against `web/dom.js` under jsdom. It pins the
reconciler's properties directly: a differently keyed child gets a new node rather than
inheriting one and its listener, a keyed row that moves is moved rather than rewritten, a
control with a write in flight is left alone, a node a click left behind survives a render,
and the picker reads its value before its children are reconciled. Every one of those was
mutation-tested — the code was broken deliberately and the test was required to fail.

What it cannot reach is everything below. jsdom has no layout, no focus ring and no text
selection, and it does not run `app.js` at all, so the checks here still cover:

- **the browser behaviours** — checks 1, 2 and 5, which are about what survives a redraw on a
  real screen rather than about what the reconciler does to a tree;
- **the wiring** — that the buttons the page actually builds carry the keys the reconciler
  needs. The unit test proves keys work; check 8 proves this page uses them.

That second gap is the one to close next, and it needs `app.js` split further before a test
can reach a renderer.

## Note on running this

The fixture sends `cache-control: no-store`, so an edit to `app.js` is picked up by a reload.
It did not always, and an ES module is cached per URL beyond an ordinary refresh — if a
change seems to have no effect, open a new tab before suspecting the change.

## What this cannot tell you

That the page is right about a real network. The fixture answers whatever it is asked and
never disagrees with itself; a control plane under load, mid-migration or behind a proxy
does. This list is about how the page behaves, not about what it says.
