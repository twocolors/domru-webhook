FROM node:lts-alpine AS builder

WORKDIR /app
COPY . .

RUN npm i

RUN npm cache clean --force
RUN npm prune --omit=dev

FROM node:lts-alpine AS release

WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/main.js ./main.js
COPY --from=builder /app/package-lock.json ./package-lock.json
COPY --from=builder /app/package.json ./package.json

CMD [ "npm", "run", "start" ]