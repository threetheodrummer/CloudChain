import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev server proxies /api to the CloudChain FastAPI backend
// (run: uvicorn app.main:app --reload --port 8000) so fetch('/api/...')
// works identically in dev and in a production build behind a reverse proxy.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
