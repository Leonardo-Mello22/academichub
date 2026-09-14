FROM nginx:alpine

# Gera um certificado autoassinado no build da imagem (ambiente de
# laboratório/controlado — em produção seria substituído por um
# certificado emitido por uma CA confiável, ex: Let's Encrypt).
RUN apk add --no-cache openssl \
    && mkdir -p /etc/nginx/certs \
    && openssl req -x509 -nodes -days 825 \
        -newkey rsa:2048 \
        -keyout /etc/nginx/certs/selfsigned.key \
        -out /etc/nginx/certs/selfsigned.crt \
        -subj "/C=BR/ST=PE/L=Recife/O=AcademicHub Lab/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

COPY nginx.conf /etc/nginx/conf.d/default.conf
