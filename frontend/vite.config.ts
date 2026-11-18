/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dashboard API (FastAPI, src/dashboard/server.py) listens on :8000.
const api = process.env.AEGIS_API ?? 'http://localhost:8000'
const proxy = {
  '/api': { target: api, changeOrigin: true },
  '/ws': { target: api.replace(/^http/, 'ws'), ws: true },
}

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
  build: { outDir: 'dist', sourcemap: false },
  test: { environment: 'node', include: ['src/**/*.test.ts'] },
})
