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

## Limitaciones a Recordar

- XSS esta limitado al motor JS del browser (V8, SpiderMonkey, etc.)
- En browsers modernos: limitado al mismo dominio (Same-Origin Policy)
- `innerHTML` bloquea tags `<script>` → usar `<img onerror>` u otros event handlers
- Stored XSS puede requerir eliminar el payload directamente de la BD para remediarlo

---

## Quick Reference — Metodologia

```
1. Identificar inputs (forms, URL params, headers)
2. Probar: <script>alert(window.origin)</script>
3. Si bloqueado: <img src="" onerror=alert(window.origin)>
4. Ver Network tab: ¿hay HTTP request? → determinar tipo
5. Recargar pagina → ¿persiste? → Stored vs Reflected
6. Revisar URL con # → DOM-based
7. Para Reflected/DOM: construir URL maliciosa para victima
8. Para Stored: verificar que afecta a otros usuarios
```
