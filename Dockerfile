FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY src ./src
COPY scripts/bundle.mjs ./scripts/bundle.mjs
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/worker/index.js ./worker/index.js
COPY scripts/server.mjs ./scripts/server.mjs
USER node
EXPOSE 3000
CMD ["node","scripts/server.mjs"]
