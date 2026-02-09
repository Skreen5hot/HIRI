import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/browser/**/*.test.ts', 'tests/unit/**/*.test.ts'],
    exclude: ['tests/unit/site.test.ts'],
    browser: {
      enabled: true,
      provider: 'playwright',
      instances: [
        { browser: 'chromium' },
      ],
    },
    globals: false,
  },
});
