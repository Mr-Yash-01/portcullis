# Nginx gateway + static UI. The unprivileged image runs as uid 101 and listens on 8080.
FROM nginxinc/nginx-unprivileged:1.31-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY static/ /usr/share/nginx/html/
