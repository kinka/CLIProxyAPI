const path = require("path");

const codexBin = path.join(process.env.HOME || "", ".bun", "bin");

module.exports = {
  apps: [
    {
      name: "cli-proxy-api",
      cwd: __dirname,
      script: "./cli-proxy-api",
      args: ["--config", "./config.yaml"],
      interpreter: "none",
      exec_mode: "fork",
      instances: 1,
      autorestart: true,
      watch: false,
      kill_timeout: 35000,
      restart_delay: 3000,
      min_uptime: "10s",
      max_restarts: 10,
      out_file: "./logs/pm2-out.log",
      error_file: "./logs/pm2-error.log",
      merge_logs: true,
      time: true,
      env: {
        PATH: [codexBin, process.env.PATH].filter(Boolean).join(path.delimiter),
      },
    },
  ],
};
