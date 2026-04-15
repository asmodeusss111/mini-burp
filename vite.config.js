import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/proxy": "http://localhost:8080",
      "/request": "http://localhost:8080",
      "/portscan": "http://localhost:8080",
      "/headers": "http://localhost:8080",
    },
  },
});
