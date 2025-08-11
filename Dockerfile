# Image officielle Playwright avec Chromium/Firefox/WebKit + deps déjà installés
FROM mcr.microsoft.com/playwright:v1.46.0-jammy

WORKDIR /app

# Installe les deps Node de notre app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# Copie le serveur
COPY server.mjs .

# Port utilisé par notre serveur Express
EXPOSE 8080

# Lance l'app
CMD ["node", "server.mjs"]
