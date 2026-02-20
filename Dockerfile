FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM deps AS build
COPY tsconfig.json tsconfig.build.json ./
COPY src/ src/
RUN npx tsc -p tsconfig.build.json

FROM deps AS dev
EXPOSE 3000
CMD ["npx", "tsx", "--watch", "src/index.ts"]

FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist/ dist/
COPY migrations/ migrations/
COPY docs/ docs/
EXPOSE 3000
CMD ["node", "dist/index.js"]
