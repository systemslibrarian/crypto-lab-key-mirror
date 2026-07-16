import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-key-mirror/',
  build: {
    target: 'es2022',
  },
  test: {
    include: ['src/**/*.test.ts'],
  },
});
