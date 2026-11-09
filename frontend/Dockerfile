# Das Frontend ist plattformunabhängig: immer nativ bauen (unter ARM-Emulation stürzt Node ab)
FROM --platform=$BUILDPLATFORM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
COPY . .
RUN npm run build

FROM nginx:1.29-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY page-headers.conf /etc/nginx/snippets/page-headers.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
