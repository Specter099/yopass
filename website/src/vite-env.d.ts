/// <reference types="vite/client" />

// Injected at build time via `define` in vite.config.ts — not the Node.js
// process global. Keep in sync with the keys defined there.
declare const process: {
  env: {
    CI?: string;
    NODE_ENV?: string;
    YOPASS_BACKEND_URL?: string;
  };
};
