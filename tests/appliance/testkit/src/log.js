"use strict";

// Tiny logging + RNG + timing helpers shared across the runner.

function ts() {
  return new Date().toISOString().replace("T", " ").replace("Z", "");
}

function info(...args) {
  // eslint-disable-next-line no-console
  console.log(`[${ts()}]`, ...args);
}

function warn(...args) {
  // eslint-disable-next-line no-console
  console.warn(`[${ts()}] WARN`, ...args);
}

function error(...args) {
  // eslint-disable-next-line no-console
  console.error(`[${ts()}] ERROR`, ...args);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Small deterministic-ish RNG (mulberry32) so a SEED reproduces the population.
function makeRng(seed) {
  let a = seed >>> 0;
  if (a === 0) a = (Date.now() & 0xffffffff) >>> 0;
  return function rng() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng, min, max) {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function pick(rng, arr) {
  return arr[Math.floor(rng() * arr.length)];
}

module.exports = { info, warn, error, sleep, makeRng, randInt, pick };
