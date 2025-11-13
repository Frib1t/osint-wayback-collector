# 🤝 Contribuciones
Pull Requests bienvenidos
Si añades mejoras, las integro al toolkit ✨

# 👤 Autor
**Ramón Frizat – Frib1t**  
_OSINT • Pentesting • Python_
Si estas herramientas te sirven en tus labs o auditorías:  
⭐ **Déjame una estrellita en GitHub, es el mejor agradecimiento.**

----

# 🧨 OSINT Toolkit – Wayback Collector & URL Checker  
**Dos herramientas OSINT en Python 3 para auditorías autorizadas**

> **Autor:** Ramón Frizat (aka Frib1t)  
> **Lenguaje:** Python 3  
> **Dependencias:** `requests`, `pwntools`  
> **Licencia:** Uso ético y autorizado únicamente

---

## ⚠️ **Aviso Legal**

> **El uso de estas herramientas contra sistemas sin autorización explícita puede ser ilegal.**  
> El autor y los colaboradores **no se hacen responsables** del uso inadecuado.  
> Úsalas **solo** en:
> - Infraestructuras propias
> - Laboratorios controlados
> - Entornos con **permiso por escrito**

---

# 🛰️ 1. `archive.py` – OSINT Wayback URL Collector v4.0
Herramienta para recolectar URLs históricas desde Wayback Machine usando la API CDX.

## ✨ Características principales
- 🎯 Recopilación masiva de URLs archivadas
- 📊 Barra de progreso dinámica con pwntools
- 📁 Soporta un dominio (-u) o miles (-i o stdin)
- 🔁 Reintentos automáticos
- 🚫 Eliminación de duplicados
- 💤 Delay configurable
- 💾 Guarda automáticamente en .txt

---

## 📦 Instalación de dependencias
```bash
pip3 install requests pwntools
```
---
## 🔧 Instalación
```bash
git clone https://github.com/Frib1t/osint-wayback-collector.git
cd osint-wayback-collector
chmod +x archive.py
```
---

## 🚀 Uso
```bash
# Un dominio
python3 archive.py -u nasa.org

# Archivo de subdominios
python3 archive.py -i subs.txt -o urls.txt

# Desde pipe
cat subs.txt | python3 archive.py -o urls_pipe.txt

# Más rápido (menos delay)
python3 archive.py -i subs.txt --sleep 5 --max-retry 2
```

## 🛠️ Parámetros
| Opción | Descripción|
|--------|------------|
|`-u`, `--url` | Un solo dominio|
|`-i`, `--input` | Archivo o - para stdin|
|`-o`, `--output` | Salida (default: URLS.txt)|
|`--sleep` | Segundos entre dominios (default: 15)|
|`--max-retry` | Reintentos (default: 3)|
|`--no-color` | Sin colores|

## 📤 Ejemplo visual de salida
```bash
╔═══════════════════════════════════════════════════════════╗
║          OSINT Wayback URL Collector v4.0                 ║
║      URLs históricas con barra de progreso                ║
╚═══════════════════════════════════════════════════════════╝

Recolectando: 1/1 → lacamara.es
URLs encontradas: 487 URLs
Recolectando: Completado: 1 dominios
URLs encontradas: Total: 487 URLs → URLS.txt
```

------
 
# 🔍 2. `artive.py` – OSINT URL Checker v1.0
Verifica URLs activas y detecta parámetros inyectables (SQLi, XSS, LFI, etc.).

## ✨ Características

- ⚡ Multihilo (30 hilos por defecto)
- 🔁 Fallback automático: HEAD → GET
- 🕵 Detecta parámetros como:
  `id=, q=, file=, page=, user=, etc.`
- 💾 Archivos generados:
  - active.txt → URLs activas
  - vulnerable_params.txt → URLs con parámetros sospechosos
- 📊 Barra de progreso real
- 📡 Soporta pipes y wordlists enormes

## 📦 Instalación de dependencias
```bash
pip3 install requests pwntools
```
---
## 🔧 Instalación
```bash
git clone https://github.com/Frib1t/osint-url-checker.git
cd osint-url-checker
chmod +x active.py
```
---
## 🚀 Uso
```bash
# Desde archivo
python3 active.py -i URLS.txt

# Desde pipe (ideal con archive.py)
python3 archive.py -u nasa.org | python3 active.py

# Personalizado
python3 active.py -i urls.txt -o nasa_active.txt --vuln-output nasa_vuln.txt -t 50
```
## 🛠️ Parámetros
| Opción            | Descripción                                      |
|-------------------|--------------------------------------------------|
| `-i`, `--input`   | Archivo o `-` para stdin                         |
| `-o`, `--output`  | Salida activas (default: `active.txt`)           |
| `--vuln-output`   | Salida vulnerables (default: `vulnerable_params.txt`) |
| `-t`, `--threads` | Hilos (default: 30)                              |
| `--timeout`       | Segundos por URL (default: 7)                    |
| `--no-color`      | Sin colores                                      |

## 📤 Ejemplo visual de salida
```bash
╔═══════════════════════════════════════════════════════════╗
║                  OSINT URL Checker v1.0                   ║
║     Verifica URLs activas + Parámetros inyectables        ║
╚═══════════════════════════════════════════════════════════╝

Verificando URLs: 20075/20075 verificadas
Activas: 342 activas → active.txt
Con parámetros: 28 con parámetros → vulnerable_params.txt
```
----
# 🔗 Pipeline OSINT Recomendada
✔ En dos pasos:
```bash
# 1. Recolectar URLs históricas
python3 archive.py -u lacamara.es > URLS.txt

# 2. Verificar activas + parámetros
python3 active.py -i URLS.txt -o lacamara_active.txt
```
✔ O en una sola línea (perfecto para automatizar):
```bash
python3 archive.py -u lacamara.es | python3 active.py -o lacamara_active.txt
```
----

# 🧭 Roadmap (Próximas mejoras)

- `--filter php,asp,aspx` → filtrar por extensión
- `--random-ua` → rotación automática de User-Agent
- `--stop-on-first` → detener al encontrar un parámetro crítico
- `--stats` → velocidad, tiempo total, media por dominio
- Integración directa con:
  - sqlmap
  - xsser
  - nuclei
  - gf patterns

---

