import logging
import os
import requests
import nmap
import urllib.parse
from telegram import Update, ReplyKeyboardRemove
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler
from fpdf import FPDF

# --- CONFIGURACIÓN ---
TOKEN_TELEGRAM = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
API_NETLAS = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
LEAKS_DIR = "leaks/"

# Estados para la interactividad
ESPERANDO_SCAN, ESPERANDO_LOGINS, ESPERANDO_EXPLOIT, ESPERANDO_BUGS, ESPERANDO_WEB = range(5)

if not os.path.exists(LEAKS_DIR):
    os.makedirs(LEAKS_DIR)

# --- CLASE PDF PROFESIONAL (Para comandos de Auditoría) ---
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.set_text_color(30, 30, 30)
        self.cell(0, 10, 'ZENITH TITAN v73.0 - AUDIT REPORT', 0, 1, 'C')
        self.ln(10)

def generate_pdf(filename, content, title, admin_highlight=False):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, title, 0, 1)
    pdf.ln(5)
    
    admin_keys = ["admin", "root", "manager", "dashboard", "wp-login", "panel", "config", "login", "portal"]
    
    for line in content:
        if admin_highlight and any(k in line.lower() for k in admin_keys):
            pdf.set_font("Arial", 'B', 9)
            pdf.set_text_color(255, 0, 0)
            pdf.multi_cell(0, 7, txt=f"[CRITICO] {line}")
        else:
            pdf.set_font("Arial", size=9)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(0, 7, txt=line)
    pdf.output(filename)

# --- COMANDOS INICIALES ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "👑 *Zenith Titan v73.0 ACTIVO*\n\n"
        "🟢 `/scan` - Ver todas las URLs e IPs de la empresa\n"
        "📊 `/status` - Estado del sistema\n"
        "🔓 `/logins` - Ver URLs con Correo y Contraseña\n"
        "💀 `/exploit` - Buscar PoCs de CVEs\n"
        "🎯 `/find_bugs` - Auditoría Pro PDF\n"
        "🌐 `/search_web` - Búsqueda en Combos\n"
        "📩 `/upload_combo` - Subir base de datos"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    archivos = len([f for f in os.listdir(LEAKS_DIR) if f.endswith('.txt')])
    await update.message.reply_text(f"📊 *Estado:* \n• APIs: Online (Netlas)\n• Archivos en Base: {archivos}\n• Motor: Titan v73.0 Deep Scan")

# --- PROCESAMIENTO ACTUALIZADO (SCAN & LOGINS POR MENSAJE) ---

async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🌐 *Mapeo de Red:* Inserta la URL o Dominio:")
    return ESPERANDO_SCAN

async def proc_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = update.message.text.strip()
    await update.message.reply_text(f"🛰 *Escaneando infraestructura y archivos sensibles en:* `{target}`...")
    
    headers = {'X-API-Key': API_NETLAS}
    url_netlas = f"https://app.netlas.io/api/domains/?q=domain:*.{target}"
    
    # Lista de archivos críticos a buscar
    critical_files = [
        "/.env", "/.git/config", "/phpinfo.php", "/wp-config.php.bak", 
        "/.htaccess", "/config.json", "/admin/.htpasswd", "/.ssh/id_rsa"
    ]
    
    try:
        res = requests.get(url_netlas, headers=headers).json()
        items = res.get('items', [])
        
        if not items:
            await update.message.reply_text("❌ No se hallaron subdominios.")
            return ConversationHandler.END

        mensaje = f"🌐 *INFRAESTRUCTURA HALLADA:* `{target}`\n\n"
        
        for i in items[:15]: # Limitamos a los primeros 15 para el análisis de archivos
            domain = i['data'].get('domain', 'N/A')
            ip = i['data'].get('ip', i['data'].get('a', 'Desconocida'))
            mensaje += f"📍 `{domain}` | IP: `{ip}`\n"
            
            # Intentar buscar archivos sensibles en el dominio encontrado
            # Nota: Solo probamos con el primer archivo de la lista para no ser bloqueados rápido
            found_secrets = []
            for path in [critical_files[0], critical_files[1]]: # .env y .git
                test_url = f"https://{domain}{path}"
                try:
                    # Timeout corto para no trabar el bot
                    r = requests.get(test_url, timeout=2, verify=False)
                    if r.status_code == 200 and ("DB_PASSWORD" in r.text or "[core]" in r.text):
                        found_secrets.append(f"🔥 ¡EXPUESTO! -> {path}")
                except:
                    continue
            
            if found_secrets:
                for s in found_secrets:
                    mensaje += f"   └── {s}\n"
            mensaje += "\n"

        if len(mensaje) > 4096:
            for x in range(0, len(mensaje), 4096):
                await update.message.reply_text(mensaje[x:x+4096], parse_mode="Markdown")
        else:
            await update.message.reply_text(mensaje, parse_mode="Markdown")

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")
        
    return ConversationHandler.END

async def cmd_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔓 *Deep Web Scraper:* Inserta la URL o dominio de la empresa:")
    return ESPERANDO_LOGINS

async def proc_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.message.text.strip().lower()
    await update.message.reply_text(f"📡 *Extrayendo datos reales para:* `{query}`...")
    
    encontrados = []

    # 1. BÚSQUEDA EN BASE LOCAL (Tus archivos .txt)
    if os.path.exists(LEAKS_DIR):
        for archivo in os.listdir(LEAKS_DIR):
            if archivo.endswith(".txt"):
                path = os.path.join(LEAKS_DIR, archivo)
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if query in line.lower():
                            encontrados.append(f"📁 [LOCAL] `{line.strip()}`")
                        if len(encontrados) >= 30: break

    # 2. RASTREO REAL EN FUENTES DE LEAKS (Scraping de Dumps Públicos)
    # Utilizamos un motor de búsqueda que filtra resultados de sitios de "Paste" donde se suben leaks
    try:
        # Buscamos patrones reales de emails y passwords asociados al dominio
        search_url = f"https://www.google.com/search?q=site:pastebin.com OR site:github.com + \"{query}\" + \"password\""
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(search_url, headers=headers, timeout=5)
        
        # Extraer posibles correos:pass con expresiones regulares del contenido web
        raw_leaks = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[a-zA-Z0-9._%-]+', response.text)
        
        for leak in raw_leaks:
            if query in leak:
                encontrados.append(f"🌐 [WEB-LEAK] `{leak}`")
    except Exception as e:
        print(f"Error en Scraper: {e}")

    # 3. RESPUESTA AL USUARIO
    if encontrados:
        res_msg = f"🔥 *REGISTROS ENCONTRADOS:* `{query.upper()}`\n\n"
        # Eliminar duplicados y unir
        for item in list(set(encontrados))[:40]: 
            res_msg += f"{item}\n\n"
        
        if len(res_msg) > 4096:
            for x in range(0, len(res_msg), 4096):
                await update.message.reply_text(res_msg[x:x+4096], parse_mode="Markdown")
        else:
            await update.message.reply_text(res_msg, parse_mode="Markdown")
    else:
        await update.message.reply_text(f"❌ No se hallaron credenciales activas en Clearnet o Base Local para `{query}`.")
    
    return ConversationHandler.END"✅ No se hallaron credenciales para `{query}`.")
    return ConversationHandler.END

# --- COMANDOS RESTANTES (SIN CAMBIOS) ---

async def cmd_exploit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("💀 *Exploit Engine:* Inserta el software o CVE:")
    return ESPERANDO_EXPLOIT

async def proc_exploit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.message.text
    url = f"https://sploitus.com/search?query={urllib.parse.quote(query)}"
    await update.message.reply_text(f"💀 *PoCs encontrados:* [Ver en Sploitus]({url})", parse_mode="Markdown")
    return ConversationHandler.END

async def cmd_find_bugs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🎯 *Auditoría:* Inserta la IP:")
    return ESPERANDO_BUGS

# Reemplaza solo la función proc_find_bugs en tu script actual

async def proc_find_bugs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip = update.message.text.strip()
    await update.message.reply_text(f"🎯 *Iniciando Auditoría Profunda en {ip}...*\nEste proceso es exhaustivo. Por favor, espera.")
    
    nm = nmap.PortScanner()
    try:
        # Escaneo real con detección de versiones y vulnerabilidades
        nm.scan(ip, arguments='-sV -T4 --script vuln')
        
        results = []
        for host in nm.all_hosts():
            results.append(f"HOST: {host} ({nm[host].hostname()})")
            results.append(f"ESTADO: {nm[host].state().upper()}")
            results.append("-" * 30)
            
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    srv = nm[host][proto][port]
                    product = srv.get('product', 'Desconocido')
                    version = srv.get('version', '')
                    
                    linea = f"Puerto {port}/{proto}: {srv['state'].upper()} | {product} {version}"
                    results.append(linea)
                    
                    if 'script' in srv:
                        for script_id, output in srv['script'].items():
                            results.append(f"   ⚠️ VULN DETECTADA [{script_id}]:")
                            # LIMPIEZA DE CARACTERES: Reemplaza cualquier caracter no compatible para evitar el error 'latin-1'
                            clean_output = output.encode('ascii', 'ignore').decode('ascii')
                            results.append(f"   {clean_output[:400]}")
                    results.append("")

        if not results:
            await update.message.reply_text("❌ No se obtuvieron resultados. Verifica la IP.")
            return ConversationHandler.END

        # Generar PDF seguro contra errores de codificación
        pdf_name = f"VULN_REAL_{ip.replace('.', '_')}.pdf"
        
        # Ajuste interno de PDF para ignorar caracteres fallidos
        pdf = PDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, f"AUDITORIA TECNICA: {ip}", 0, 1)
        pdf.ln(5)
        pdf.set_font("Arial", size=9)
        
        for r in results:
            # Forzamos que cada línea sea compatible con el PDF
            safe_text = r.encode('latin-1', 'ignore').decode('latin-1')
            pdf.multi_cell(0, 6, txt=safe_text)
            
        pdf.output(pdf_name)
        
        await update.message.reply_document(
            document=open(pdf_name, 'rb'), 
            caption=f"📊 *Auditoría Real Finalizada*\nIP: {ip}\n\nRevisa el reporte para hallar CVEs y fallos de configuración."
        )
        os.remove(pdf_name)
        
    except Exception as e:
        # Imprime el error exacto en consola para debug y avisa al usuario
        print(f"DEBUG ERROR: {e}")
        await update.message.reply_text(f"❌ Error en el motor: {str(e)}")
    
    return ConversationHandler.END

async def cmd_search_web(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📂 *Búsqueda Local:* Inserta término:")
    return ESPERANDO_WEB

async def upload_combo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📩 Envía el archivo .txt con los combos.")

async def handle_docs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if doc.file_name.endswith(".txt"):
        path = os.path.join(LEAKS_DIR, doc.file_name)
        new_file = await context.bot.get_file(doc.file_id)
        await new_file.download_to_drive(path)
        await update.message.reply_text(f"✅ Base de datos actualizada con: `{doc.file_name}`.")

# --- MAIN ---
if __name__ == '__main__':
    app = Application.builder().token(TOKEN_TELEGRAM).build()

    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("scan", cmd_scan),
            CommandHandler("logins", cmd_logins),
            CommandHandler("exploit", cmd_exploit),
            CommandHandler("find_bugs", cmd_find_bugs),
            CommandHandler("search_web", cmd_search_web)
        ],
        states={
            ESPERANDO_SCAN: [MessageHandler(filters.TEXT & ~filters.COMMAND, proc_scan)],
            ESPERANDO_LOGINS: [MessageHandler(filters.TEXT & ~filters.COMMAND, proc_logins)],
            ESPERANDO_EXPLOIT: [MessageHandler(filters.TEXT & ~filters.COMMAND, proc_exploit)],
            ESPERANDO_BUGS: [MessageHandler(filters.TEXT & ~filters.COMMAND, proc_find_bugs)],
            ESPERANDO_WEB: [MessageHandler(filters.TEXT & ~filters.COMMAND, proc_logins)],
        },
        fallbacks=[CommandHandler("cancel", lambda u,c: ConversationHandler.END)]
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("upload_combo", upload_combo))
    app.add_handler(conv_handler)
    app.add_handler(MessageHandler(filters.Document.ALL, handle_docs))
    
    print("Zenith Titan v73.0 Online...")
    app.run_polling()
