FROM node:22-alpine
RUN apk add --no-cache git
RUN git clone --depth 1 https://github.com/sercansolmaz/archive-todo.git /app
WORKDIR /app
ENV PORT=3001 DATA_DIR=/app/data
EXPOSE 3001
CMD ["node", "server.js"]
