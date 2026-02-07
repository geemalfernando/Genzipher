import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3001,
    proxy: {
      '/auth': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      '/pharmacy': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      '/pharmacist': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      '/biometric': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      '/demo': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
  },
  // Keep this app self-contained (don’t read assets from the parent repo’s `public/`).
  publicDir: 'public',
})
