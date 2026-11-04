import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// API target is overridable (e.g. when :8000 is taken): TRACEX_API=http://127.0.0.1:8010
const API = process.env.TRACEX_API || 'http://127.0.0.1:8000'
const routes = ['/events', '/graph', '/report', '/analysis', '/timeline', '/cases', '/health', '/live', '/assurance', '/integrity', '/compare', '/review']

export default defineConfig({
  plugins: [react()],
  server: { proxy: Object.fromEntries(routes.map((r) => [r, API])) },
})
