import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Test environment
    environment: 'node',

    // Global test setup
    globals: true,

    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.d.ts',
        'src/**/*.test.ts',
        'src/**/*.spec.ts'
      ],
      thresholds: {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80
        }
      }
    },

    // Test file patterns
    include: [
      'tests/**/*.test.ts',
      'tests/**/*.spec.ts'
    ],

    // Setup files
    setupFiles: ['./tests/setup.ts'],

    // TypeScript support
    typecheck: {
      tsconfig: './tsconfig.json'
    }
  }
});