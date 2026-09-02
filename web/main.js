/**
 * What index.html loads.
 *
 * The whole page is app.js; this exists so that app.js can be imported without running.
 * A module that starts polling and attaches listeners the moment it is loaded is a module
 * a test can only observe through a browser, which is how the renderers went untested
 * while the reconciler beneath them did not (ADR-0032 §6).
 */
import { bootstrap } from "./app.js";

bootstrap();
