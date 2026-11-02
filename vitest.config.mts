import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 60_000,
    fileParallelism: false,
    coverage: { provider: 'v8', include: ['src/**'], thresholds: { lines: 90, branches: 85, functions: 90 } },
  },
});