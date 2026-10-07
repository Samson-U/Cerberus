import path from 'node:path'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: '0.0.0.0',
    port: Number.parseInt(process.env.PORT || '5173', 10),
    strictPort: false,
  },
  preview: {
    host: '0.0.0.0',
    port: Number.parseInt(process.env.PORT || '5173', 10),
  },
})
