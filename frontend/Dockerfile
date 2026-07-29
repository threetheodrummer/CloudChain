# CloudChain frontend: build with Node, serve the static bundle with nginx.
FROM node:20-alpine AS build

WORKDIR /app

# npm ci needs both files and respects the lockfile exactly, which is what
# makes a container build reproducible.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build


FROM nginx:1.27-alpine AS runtime

# The app is a single-page build; nginx also proxies /api to the backend so the
# browser sees one origin and there is no CORS involved in production.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://127.0.0.1/ || exit 1
