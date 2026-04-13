FROM node:20-slim

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY . .

EXPOSE 3000

# 啟動 SOC Dashboard 代理
CMD ["node", "soc-server.js"]
