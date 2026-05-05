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
      "/health": "http://localhost:8080",
      "/fuzz": "http://localhost:8080",
      "/ssl": "http://localhost:8080",
      "/whois": "http://localhost:8080",
      "/history": "http://localhost:8080",
      "/report": "http://localhost:8080",
      "/report-save": "http://localhost:8080",
      "/api": "http://localhost:8080",
    },
  },
});
