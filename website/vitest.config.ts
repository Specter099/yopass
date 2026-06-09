import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@shared': path.resolve(__dirname, 'src/shared'),
      '@features': path.resolve(__dirname, 'src/features'),
    },
  },
  test: {
    // Playwright owns tests/; vitest only runs unit tests colocated in src/.
    include: ['src/**/*.test.{ts,tsx}'],
    environment: 'node',
  },
});
