"use strict";

const readline = require("readline");

// Ask a single question on the terminal and resolve with the trimmed answer.
// Resolves to "" on EOF (Ctrl-D) so callers can treat that as "quit".
function ask(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    let answered = false;
    rl.question(question, (answer) => {
      answered = true;
      rl.close();
      resolve((answer || "").trim());
    });
    // `rl.close()` above emits 'close' synchronously, so only treat a close as
    // EOF ("") when the question was never actually answered. Without this
    // guard the close handler would resolve "" first and clobber every answer.
    rl.on("close", () => {
      if (!answered) resolve("");
    });
  });
}

module.exports = { ask };
