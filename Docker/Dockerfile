# Base image: Node.js 18 Alpine (leggero, ~40MB)
FROM node:18-alpine

# Installa ipmitool per eseguire i comandi IPMI in Linux/Docker
RUN apk add --no-cache ipmitool

# Imposta la cartella di lavoro nel container
WORKDIR /app

# Copia i file package
COPY package*.json ./

# Installa le dipendenze (solo produzione)
RUN npm ci --only=production

# Copia i file dell'applicazione
COPY server.js ./
COPY public/ ./public/

# Esponi la porta 3000
EXPOSE 3000

# Health check - verifica che l'app sia funzionante
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/api/health', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})"

# Comando da eseguire all'avvio del container
CMD ["node", "server.js"]