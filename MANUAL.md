# dnscacheo — Manual de Implementación
**DNS Cache Server con Zero Trust para Grupo Barone SRL**

---

## Índice

1. [Requisitos](#1-requisitos)
2. [Instalación](#2-instalación)
3. [Configuración](#3-configuración)
4. [Levantar el servidor](#4-levantar-el-servidor)
5. [Panel de administración web](#5-panel-de-administración-web)
6. [Políticas Zero Trust](#6-políticas-zero-trust)
7. [Rate Limiting](#7-rate-limiting)
8. [DNS Cifrado — DoT y DoH](#8-dns-cifrado--dot-y-doh)
9. [IPv6](#9-ipv6)
10. [Detección de DNS Tunneling](#10-detección-de-dns-tunneling)
11. [Métricas — Prometheus y Grafana](#11-métricas--prometheus-y-grafana)
12. [API REST](#12-api-rest)
13. [Producción con Docker](#13-producción-con-docker)
14. [Mantenimiento](#14-mantenimiento)
15. [Resolución de problemas](#15-resolución-de-problemas)

---

## 1. Requisitos

### Software

| Componente | Versión mínima | Uso |
|---|---|---|
| Go | 1.22 | Compilar y correr el servidor |
| Docker + Docker Compose | 24+ | Infraestructura (Redis, PostgreSQL, Grafana) |
| PostgreSQL | 14+ | Logs de consultas y alertas |
| Redis | 7+ | Caché DNS |
| Git | cualquiera | Clonar el repositorio |

### Puertos que usa el servidor

| Puerto | Protocolo | Función |
|---|---|---|
| 53 | UDP + TCP (IPv4) | DNS estándar |
| 53 | UDP + TCP (IPv6) | DNS estándar IPv6 |
| 853 | TCP/TLS | DNS over TLS (DoT) |
| 443 | HTTPS | DNS over HTTPS (DoH) |
| 8080 | HTTP | Panel web + API REST |
| 9090 | HTTP | Métricas Prometheus |

### Hardware recomendado (20.000 clientes)

| Recurso | Mínimo | Recomendado |
|---|---|---|
| CPU | 4 cores | 8 cores |
| RAM | 4 GB | 8 GB |
| Disco | 50 GB | 200 GB (logs) |
| Red | 100 Mbps | 1 Gbps |

---

## 2. Instalación

### 2.1 Clonar el repositorio

```bash
git clone https://github.com/baronematias81/dnscacheo.git
cd dnscacheo
```

### 2.2 Instalar Go

**Linux / Ubuntu:**
```bash
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

**Windows:**
Descargar el instalador desde https://go.dev/dl/ y ejecutarlo.

### 2.3 Descargar dependencias Go

```bash
go mod download
```

### 2.4 Levantar infraestructura con Docker

```bash
cd deployments
docker-compose up -d
cd ..
```

Esto levanta:
- **Redis** en `localhost:6379`
- **PostgreSQL** en `localhost:5432`
- **Prometheus** en `localhost:9090`
- **Grafana** en `localhost:3000`

### 2.5 Crear la base de datos

```bash
# Crear usuario y base de datos (primera vez)
docker exec -it dnscacheo-postgres psql -U postgres -c "CREATE USER dnscacheo WITH PASSWORD 'changeme';"
docker exec -it dnscacheo-postgres psql -U postgres -c "CREATE DATABASE dnscacheo OWNER dnscacheo;"

# Aplicar migraciones
psql -h localhost -U dnscacheo -d dnscacheo -f internal/db/migrations/001_init.sql
psql -h localhost -U dnscacheo -d dnscacheo -f internal/db/migrations/002_tunnel_alerts.sql
```

### 2.6 Compilar el servidor

```bash
go build -o dnscacheo ./cmd/server
```

---

## 3. Configuración

Toda la configuración está en `config/config.yaml`. A continuación se explica cada sección.

### 3.1 Servidor DNS

```yaml
server:
  listen_udp4: "0.0.0.0:53"    # Puerto DNS UDP IPv4
  listen_tcp4: "0.0.0.0:53"    # Puerto DNS TCP IPv4
  ipv6_enabled: true            # Activar soporte IPv6
  listen_udp6: "[::]:53"        # Puerto DNS UDP IPv6
  listen_tcp6: "[::]:53"        # Puerto DNS TCP IPv6
  timeout: "2s"                 # Timeout de consultas upstream

  upstreams4:                   # Servidores DNS IPv4 de respaldo
    - "1.1.1.1:53"              # Cloudflare
    - "8.8.8.8:53"              # Google
    - "9.9.9.9:53"              # Quad9

  upstreams6:                   # Servidores DNS IPv6 de respaldo
    - "[2606:4700:4700::1111]:53"
    - "[2001:4860:4860::8888]:53"
    - "[2620:fe::fe]:53"
```

### 3.2 Caché Redis

```yaml
cache:
  redis_url: "redis://localhost:6379"
  default_ttl: 300              # Segundos de TTL por defecto
  max_ttl: 86400                # TTL máximo (24 horas)
```

### 3.3 Base de datos

```yaml
database:
  host: "localhost"
  port: 5432
  name: "dnscacheo"
  user: "dnscacheo"
  password: "changeme"
```

### 3.4 TLS (para DoT y DoH)

```yaml
tls:
  enabled: true
  cert_file: "certs/server.crt"    # Dejar vacío para autogenerar
  key_file: "certs/server.key"     # Dejar vacío para autogenerar
  auto_generate: true              # Genera cert autofirmado si no existe
  min_version: "1.2"               # Versión TLS mínima: "1.2" o "1.3"
  sans:                            # Nombres/IPs en el certificado
    - "dns.grupobaron.com.ar"
    - "192.168.1.1"
    - "::1"
```

> **Nota:** Si tenés un certificado real (Let's Encrypt, etc.), colocá los archivos
> en las rutas indicadas y desactivá `auto_generate: false`.

### 3.5 DNS over TLS (DoT)

```yaml
dot:
  enabled: true
  listen: "0.0.0.0:853"
  ipv6_enabled: true
  listen_ipv6: "[::]:853"
  timeout: "10s"
```

### 3.6 DNS over HTTPS (DoH)

```yaml
doh:
  enabled: true
  listen: "0.0.0.0:443"
  ipv6_enabled: true
  listen_ipv6: "[::]:443"
  path: "/dns-query"
  listen_plain: ""               # Para proxy TLS externo (nginx/Traefik)
```

### 3.7 Rate Limiting

```yaml
rate_limit:
  enabled: true
  global_rate: 100               # Consultas/segundo por cliente
  global_burst: 200              # Ráfaga máxima
  cleanup_interval: 60           # Segundos entre limpieza de buckets
  idle_timeout: 300              # Segundos hasta liberar bucket inactivo

  per_client_rates:
    - cidr: "192.168.0.0/16"
      rate: 500
      burst: 1000
    - cidr: "10.0.0.0/8"
      rate: 200
      burst: 400
```

### 3.8 Filtros

```yaml
filter:
  enabled: true
  categories:
    malware: true                # Bloquear dominios de malware
    ads: true                    # Bloquear publicidad
    adult: false                 # Bloquear contenido adulto
    gambling: false              # Bloquear apuestas
```

### 3.9 Zero Trust

```yaml
zero_trust:
  enabled: true
  require_encrypted: false       # true = solo acepta DoT/DoH
  default_policy: "allow"        # "allow" o "block"
```

### 3.10 Detección de DNS Tunneling

```yaml
tunnel_detection:
  enabled: true
  entropy_min: 3.8               # Umbral de entropía de Shannon
  label_len_min: 45              # Largo mínimo de label sospechosa
  unique_subs_window: 60         # Ventana en segundos
  unique_subs_min: 40            # Subdominios únicos para alertar
  query_rate_window: 60          # Ventana en segundos
  query_rate_min: 150            # Consultas para alertar
```

### 3.11 Métricas

```yaml
metrics:
  enabled: true
  listen: "0.0.0.0:9090"
```

---

## 4. Levantar el servidor

### Modo desarrollo

```bash
go run ./cmd/server -config config/config.yaml
```

### Modo producción (binario compilado)

```bash
# Compilar
go build -o dnscacheo ./cmd/server

# Ejecutar
./dnscacheo -config config/config.yaml
```

### Como servicio systemd (Linux)

Crear el archivo `/etc/systemd/system/dnscacheo.service`:

```ini
[Unit]
Description=dnscacheo DNS Cache Server
After=network.target redis.service postgresql.service

[Service]
Type=simple
User=dnscacheo
WorkingDirectory=/opt/dnscacheo
ExecStart=/opt/dnscacheo/dnscacheo -config /opt/dnscacheo/config/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable dnscacheo
sudo systemctl start dnscacheo
sudo systemctl status dnscacheo
```

### Verificar que funciona

```bash
# Consulta DNS básica
dig @localhost google.com

# Consulta por IPv6
dig @::1 google.com

# Verificar DoH
curl -s "https://localhost/dns-query?dns=$(echo -n 'AAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ==' | base64 -d | base64 -w0)" \
  --cacert certs/server.crt -o /dev/null -w "%{http_code}"
```

---

## 5. Panel de administración web

Acceder en: **http://servidor:8080**

### Secciones disponibles

#### Dashboard
Vista general con métricas de las últimas 24 horas:
- Total de consultas, cache hit rate, consultas bloqueadas, clientes activos
- Gráfico de consultas por hora
- Distribución caché / upstream / bloqueadas
- Top 5 clientes y dominios

#### Logs de consultas
Historial completo con filtros:
- Filtrar por IP de cliente
- Filtrar por dominio (soporta `%patron%`)
- Seleccionar cantidad de registros (50, 100, 500)

#### Clientes
Actividad por IP en las últimas 24h:
- Total consultas, cache hits, bloqueadas, dominios únicos
- Latencia promedio y última consulta

#### Top dominios
Los 50 dominios más consultados con porcentaje de cache hit.

#### Bloqueados
Dominios bloqueados más intentados, con categoría (malware, ads, policy).

#### DNS Tunneling
Alertas de detección activas con score, tipo de algoritmo y detalles.
Botón "Resolver" para marcar como revisado.

#### Rate Limiting
Estado del rate limiter, clientes con más rechazos.

#### Cifrado DoT / DoH
Estado de los protocolos cifrados y snippet de configuración.

#### Políticas Zero Trust
Crear y eliminar reglas por IP o CIDR (IPv4 e IPv6).

#### Caché
Limpiar el caché completo o eliminar un dominio específico.

---

## 6. Políticas Zero Trust

Las políticas permiten controlar qué puede resolver cada cliente.

### Crear una política desde el panel web

1. Ir a **Políticas Zero Trust**
2. Completar IP o subred (ej: `192.168.1.50` o `10.0.0.0/8` o `2001:db8::/32`)
3. Elegir **Permitir todo** o **Bloquear todo**
4. Configurar bloqueo de adultos y rate limit
5. Hacer clic en **Guardar política**

### Crear una política desde la API

```bash
# Bloquear todo excepto lista blanca para una IP
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "client_ip": "192.168.1.100",
    "allow_all": false,
    "whitelist": ["google.com", "*.microsoft.com"],
    "rate_limit": 50
  }'

# Subred con acceso completo pero bloqueando adultos
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "client_ip": "10.0.1.0/24",
    "allow_all": true,
    "block_adult": true,
    "rate_limit": 200
  }'

# Eliminar política
curl -X DELETE http://localhost:8080/api/v1/policies/192.168.1.100
```

---

## 7. Rate Limiting

El rate limiter usa el algoritmo **Token Bucket**:
- Cada cliente tiene un bucket que se llena a `rate` tokens/segundo
- Cada consulta consume 1 token
- Si el bucket se vacía, la consulta se rechaza con `REFUSED`
- Los buckets se limpian automáticamente después de `idle_timeout` segundos sin actividad

### Calcular los valores correctos

Para un cliente residencial normal:
```
rate: 20     # 20 consultas por segundo es más que suficiente
burst: 50    # permite ráfagas al cargar una página web
```

Para una empresa o servidor:
```
rate: 200
burst: 500
```

### Agregar regla por subred en config.yaml

```yaml
rate_limit:
  per_client_rates:
    - cidr: "192.168.100.0/24"   # Servidores internos
      rate: 1000
      burst: 2000
    - cidr: "192.168.0.0/16"     # Clientes residenciales
      rate: 50
      burst: 100
```

> Reiniciar el servidor para aplicar cambios de configuración.

---

## 8. DNS Cifrado — DoT y DoH

### Activar en config.yaml

```yaml
tls:
  enabled: true
  auto_generate: true
  sans:
    - "dns.tuprovedor.com"
    - "200.1.2.3"          # IP pública del servidor

dot:
  enabled: true

doh:
  enabled: true
```

### Configurar clientes

#### Android (DoT)
1. Ajustes → Red e Internet → DNS privado
2. Seleccionar "Nombre de host del proveedor"
3. Ingresar: `dns.tuprovedor.com`

#### iOS (DoH)
Instalar un perfil de configuración o usar una app como **NextDNS** apuntando a tu servidor.

#### Firefox (DoH)
1. Preferencias → General → Configuración de red → Configuración
2. Activar "Activar DNS sobre HTTPS"
3. URL personalizada: `https://dns.tuprovedor.com/dns-query`

#### Windows 11 (DoH)
1. Configuración → Red e Internet → Wi-Fi → Propiedades de hardware
2. Editar asignación de servidor DNS
3. DNS preferido: IP del servidor
4. Cifrado DNS: `HTTPS` — URL: `https://dns.tuprovedor.com/dns-query`

#### Linux con systemd-resolved (DoT)
Editar `/etc/systemd/resolved.conf`:
```ini
[Resolve]
DNS=IP_DEL_SERVIDOR
DNSOverTLS=yes
```
```bash
sudo systemctl restart systemd-resolved
```

### Usar certificado real (Let's Encrypt)

```bash
# Obtener certificado con certbot
certbot certonly --standalone -d dns.tuprovedor.com

# En config.yaml
tls:
  enabled: true
  cert_file: "/etc/letsencrypt/live/dns.tuprovedor.com/fullchain.pem"
  key_file:  "/etc/letsencrypt/live/dns.tuprovedor.com/privkey.pem"
  auto_generate: false
```

---

## 9. IPv6

### Verificar conectividad IPv6

```bash
# El servidor debe responder en IPv6
dig @::1 google.com AAAA

# Verificar listeners activos
ss -ulnp | grep :53
```

### Configurar router/CPE para usar el servidor

Configurar en el router el servidor DNS para que distribuya por DHCP la IP del servidor tanto en IPv4 como IPv6.

### Políticas con CIDRs IPv6

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "client_ip": "2001:db8::/32",
    "allow_all": true,
    "rate_limit": 100
  }'
```

---

## 10. Detección de DNS Tunneling

El servidor detecta automáticamente intentos de usar DNS como canal encubierto de comunicación (exfiltración de datos, C2, etc.).

### Algoritmos de detección

| Algoritmo | Qué detecta | Herramientas detectadas |
|---|---|---|
| `high_entropy` | Labels con entropía > 3.8 (datos codificados) | iodine, dnscat2 |
| `long_label` | Labels de más de 45 caracteres | iodine, dns2tcp |
| `unique_subdomains` | Más de 40 subdominios únicos en 60s | Exfiltración por chunks |
| `query_rate` | Más de 150 consultas al mismo dominio en 60s | C2 keepalive |
| `suspicious_type` | Queries TXT/NULL con labels largas | dnscat2, custom tools |

### Escala de severidad

| Score | Severidad | Acción recomendada |
|---|---|---|
| 85–100 | **CRITICAL** | Bloquear IP inmediatamente, investigar |
| 70–84 | **HIGH** | Revisar urgente, posible tunneling activo |
| 55–69 | **MEDIUM** | Monitorear, puede ser falso positivo |
| 0–54 | **LOW** | Registro informativo |

### Ver alertas

- **Panel web** → DNS Tunneling
- **API:** `GET http://localhost:8080/api/v1/tunnel/alerts`
- **Logs del servidor:** las alertas HIGH y CRITICAL se loguean en tiempo real

### Resolver una alerta

```bash
# Desde el panel: botón "Resolver"
# Desde la API:
curl -X POST http://localhost:8080/api/v1/tunnel/alerts/123/resolve
```

### Ajustar umbrales (para reducir falsos positivos)

```yaml
tunnel_detection:
  entropy_min: 4.0          # Subir si hay muchos falsos positivos
  unique_subs_min: 60       # Subir para ser menos estricto
  query_rate_min: 200       # Subir si hay clientes con mucho tráfico legítimo
```

---

## 11. Métricas — Prometheus y Grafana

### Acceder a Grafana

URL: **http://servidor:3000**
Usuario: `admin`
Contraseña: `changeme` (cambiar en producción en `docker-compose.yml`)

El dashboard **dnscacheo** se carga automáticamente al iniciar Grafana.

### Métricas disponibles

```
# Consultas DNS
dns_queries_total{query_type, response_code, protocol}
dns_query_duration_seconds{query_type, source}
dns_cache_hit_ratio
dns_cache_hits_total
dns_cache_misses_total

# Clientes
dns_active_clients
dns_rate_limited_total
dns_ipv4_queries_total
dns_ipv6_queries_total

# Bloqueos
dns_blocked_queries_total{reason}

# Upstreams
dns_upstream_queries_total{upstream}
dns_upstream_errors_total{upstream}
dns_upstream_latency_seconds{upstream}

# Tunneling
dns_tunnel_alerts_total{alert_type, severity}

# Info
dns_build_info{version, empresa}
```

### Consultas PromQL útiles

```promql
# Tasa de consultas por minuto
sum(rate(dns_queries_total[1m])) * 60

# Cache hit rate en porcentaje
dns_cache_hit_ratio * 100

# Top 5 upstreams por tráfico
topk(5, rate(dns_upstream_queries_total[5m]))

# Latencia p95 por tipo de consulta
histogram_quantile(0.95, rate(dns_query_duration_seconds_bucket[5m])) by (query_type)

# Alertas de tunneling en la última hora
increase(dns_tunnel_alerts_total[1h])
```

### Cambiar la contraseña de Grafana en producción

En `deployments/docker-compose.yml`:
```yaml
environment:
  - GF_SECURITY_ADMIN_PASSWORD=MiNuevaContraseñaSegura
```
Luego: `docker-compose up -d grafana`

---

## 12. API REST

Base URL: `http://servidor:8080/api/v1`

### Logs y estadísticas

```bash
# Logs con filtros
GET /logs?client_ip=192.168.1.10&domain=%google%&limit=100

# Actividad por cliente (24h)
GET /stats/clients

# Top 50 dominios
GET /stats/top-domains

# Dominios bloqueados más intentados
GET /stats/blocked

# Estado del servidor
GET /health
```

### Políticas Zero Trust

```bash
# Listar todas las políticas
GET /policies

# Crear política
POST /policies
Body: {
  "client_ip": "192.168.1.0/24",
  "allow_all": true,
  "block_adult": false,
  "rate_limit": 100,
  "whitelist": [],
  "blacklist": []
}

# Eliminar política
DELETE /policies/:ip
```

### Caché

```bash
# Limpiar todo el caché
DELETE /cache

# Eliminar un dominio específico
DELETE /cache/dominio.com
```

### DNS Tunneling

```bash
# Ver alertas activas
GET /tunnel/alerts?limit=50

# Resolver alerta
POST /tunnel/alerts/:id/resolve

# Resumen de clientes con alertas
GET /tunnel/clients
```

---

## 13. Producción con Docker

### Levantar todo con Docker Compose

```bash
cd deployments
docker-compose up -d
```

### Ver logs de cada servicio

```bash
docker logs dnscacheo -f
docker logs dnscacheo-redis -f
docker logs dnscacheo-postgres -f
```

### Actualizar el servidor

```bash
git pull
go build -o dnscacheo ./cmd/server
docker-compose restart dnscacheo
```

### Backup de PostgreSQL

```bash
docker exec dnscacheo-postgres pg_dump -U dnscacheo dnscacheo > backup_$(date +%Y%m%d).sql
```

### Restaurar backup

```bash
docker exec -i dnscacheo-postgres psql -U dnscacheo dnscacheo < backup_20260101.sql
```

---

## 14. Mantenimiento

### Limpiar logs antiguos (PostgreSQL)

```sql
-- Eliminar logs de más de 90 días
DELETE FROM dns_query_logs WHERE timestamp < NOW() - INTERVAL '90 days';

-- Eliminar alertas de tunneling resueltas y antiguas
DELETE FROM dns_tunnel_alerts WHERE resolved = TRUE AND timestamp < NOW() - INTERVAL '30 days';

-- Agregar stats del día anterior manualmente
SELECT aggregate_daily_stats(CURRENT_DATE - 1);
```

### Programar limpieza automática con cron

```bash
crontab -e

# Agregar estas líneas:
# Agregar stats diarias a las 00:05
5 0 * * * psql -h localhost -U dnscacheo -d dnscacheo -c "SELECT aggregate_daily_stats(CURRENT_DATE - 1);"

# Limpiar logs de más de 90 días a las 03:00
0 3 * * * psql -h localhost -U dnscacheo -d dnscacheo -c "DELETE FROM dns_query_logs WHERE timestamp < NOW() - INTERVAL '90 days';"
```

### Actualizar listas de bloqueo

Las listas de malware y ads se actualizan automáticamente al iniciar el servidor.
Para forzar actualización, reiniciar el servicio.

### Verificar estado de Redis

```bash
redis-cli ping           # debe responder PONG
redis-cli info memory    # uso de memoria
redis-cli dbsize         # cantidad de entradas en caché
```

---

## 15. Resolución de problemas

### El servidor no inicia en el puerto 53

```bash
# Ver qué proceso usa el puerto 53
sudo ss -ulnp | grep :53

# En Linux, systemd-resolved puede estar usando el puerto
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
```

### No resuelve nada / SERVFAIL en todas las consultas

```bash
# Verificar conectividad a upstreams
dig @1.1.1.1 google.com
dig @8.8.8.8 google.com

# Verificar que Redis está corriendo
redis-cli ping

# Revisar logs del servidor
./dnscacheo -config config/config.yaml 2>&1 | tail -50
```

### No se guardan logs en PostgreSQL

```bash
# Verificar conexión a PostgreSQL
psql -h localhost -U dnscacheo -d dnscacheo -c "SELECT COUNT(*) FROM dns_query_logs;"

# Verificar que las tablas existen
psql -h localhost -U dnscacheo -d dnscacheo -c "\dt"
```

### DoT / DoH no funciona

```bash
# Verificar que TLS está habilitado en config.yaml
grep "enabled: true" config/config.yaml

# Verificar que los certs existen
ls -la certs/

# Probar DoH manualmente
curl -v https://localhost/dns-query \
  --cacert certs/server.crt \
  -H "Content-Type: application/dns-message" \
  --data-binary @/dev/null
```

### Grafana no muestra datos

```bash
# Verificar que Prometheus scrapeó datos
curl http://localhost:9090/metrics | grep dns_queries

# Verificar que el datasource está configurado en Grafana
# Ir a: Grafana → Configuration → Data Sources → Prometheus → Test
```

### Muchos falsos positivos de tunneling

Subir los umbrales en `config.yaml`:
```yaml
tunnel_detection:
  entropy_min: 4.2
  unique_subs_min: 80
  query_rate_min: 300
```

---

## Contacto y soporte

- **Repositorio:** https://github.com/baronematias81/dnscacheo
- **Empresa:** Grupo Barone SRL
- **Desarrollado con:** Go 1.22, Redis 7, PostgreSQL 16, Prometheus, Grafana

---

*Manual generado para dnscacheo v1.0.0*
