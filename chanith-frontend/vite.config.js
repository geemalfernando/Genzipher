import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3001,
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        // Local backend routes are mounted at `/...` (no `/api` prefix).
        // Keep frontend calls consistent with production by using `/api/...` in dev.
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
  build: {
    outDir: 'dist',
  },
  // Keep this app self-contained (don’t read assets from the parent repo’s `public/`).
  publicDir: 'public',
})
