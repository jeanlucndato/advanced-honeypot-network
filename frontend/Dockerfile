FROM node:22-alpine AS build
WORKDIR /src
COPY package*.json ./
RUN npm ci
COPY . ./
ARG VITE_HIVE_API_TOKEN
ENV VITE_HIVE_API_TOKEN=$VITE_HIVE_API_TOKEN
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 80
