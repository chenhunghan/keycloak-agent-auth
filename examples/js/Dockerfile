FROM node:22-slim AS build

WORKDIR /app
COPY package.json ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src

EXPOSE 3000
CMD ["npx", "tsx", "src/rs-standalone.ts"]
