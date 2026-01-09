import logging
import os
import re
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
    target = update.message.text.strip().lower()
    await update.message.reply_text(f"🔍 *Iniciando Inteligencia Web para:* `{target}`\nBuscando Leaks, Teléfonos y Credenciales...")

    # 1. Búsqueda de Paneles de Login y posibles fugas en Netlas
    headers = {'X-API-Key': API_NETLAS}
    # Buscamos archivos de texto o excel que podrían ser combos/leaks en el dominio
    dork_query = f"domain:*{target} AND (filetype:txt OR filetype:xls OR filetype:env)"
    url_netlas = f"https://app.netlas.io/api/responses/?q={urllib.parse.quote(dork_query)}"
    
    # 2. Construcción de Google Dorks para el usuario (links directos)
    # Esto busca correos y teléfonos indexados en la web
    dork_link = f"https://www.google.com/search?q=site:{target}+%22@gmail.com%22+OR+%22@{target}%22+OR+%22tel:%22"
    
    try:
        res = requests.get(url_netlas, headers=headers).json()
        items = res.get('items', [])
        
        mensaje = f"🔥 *INTELIGENCIA DE DATOS: {target}*\n\n"
        
        if items:
            mensaje += "📂 *ARCHIVOS SENSIBLES / LOGINS HALLADOS:*\n"
            for i in items[:10]:
                uri = i.get('data', {}).get('uri', 'N/A')
                mensaje += f"• `{uri}`\n"
        else:
            mensaje += "⚠️ No se hallaron archivos `.env` o `.xls` abiertos en Netlas.\n"

        mensaje += f"\n📱 *BÚSQUEDA DE CORREOS Y TELÉFONOS:*\n"
        mensaje += f"[Haz clic aquí para ver Leaks de {target} en Google]({dork_link})\n\n"
        
        mensaje += "💡 *CONSEJO:* Revisa los resultados de Google para encontrar archivos 'Pass.txt' o 'Contactos.xlsx' que no fueron bloqueados por el firewall."

        await update.message.reply_text(mensaje, parse_mode="Markdown", disable_web_page_preview=True)

    except Exception as e:
        await update.message.reply_text(f"❌ Error en búsqueda web: {str(e)}")
    
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
    await update.message.reply_text(f"🎯 *Iniciando Auditoría Avanzada en {ip}...*\nEscaneando servicios y buscando fallos XSS (DOM/Stored).")
    
    nm = nmap.PortScanner()
    try:
        # Mejora: Se agregan los scripts NSE personalizados que instalaste en Termux
        # vuln: escaneo general, http-dombased-xss: el script de JS, http-stored-xss: el de formularios
        args_scan = '-p80,443 -sV -T4 --max-retries 1 --script-timeout 20s --script http-dombased-xss.nse,http-stored-xss.nse'
        nm.scan(ip, arguments=args_scan)
        
        results = []
        for host in nm.all_hosts():
            results.append(f"HOST: {host} ({nm[host].hostname()})")
            results.append(f"ESTADO: {nm[host].state().upper()}")
            results.append("-" * 35)
            
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
                            # Identificar visualmente si es un hallazgo de los nuevos scripts
                            tag = "🚨" if "xss" in script_id else "⚠️"
                            results.append(f"   {tag} DETECTADO [{script_id}]:")
                            
                            # LIMPIEZA DE CARACTERES: Vital para Termux y FPDF
                            clean_output = output.encode('ascii', 'ignore').decode('ascii')
                            results.append(f"   {clean_output[:500]}") # Aumentamos a 500 caracteres para ver más detalle
                    results.append("")

        if not results:
            await update.message.reply_text("❌ No se obtuvieron resultados. Verifica que la IP sea correcta.")
            return ConversationHandler.END

        # --- GENERACIÓN DEL PDF ---
        pdf_name = f"VULN_REPORT_{ip.replace('.', '_')}.pdf"
        pdf = PDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, f"REPORTE TECNICO DE AUDITORIA: {ip}", 0, 1)
        pdf.ln(5)
        pdf.set_font("Arial", size=9)
        
        for r in results:
            # Doble capa de seguridad para la codificación
            try:
                safe_text = r.encode('latin-1', 'ignore').decode('latin-1')
                pdf.multi_cell(0, 6, txt=safe_text)
            except:
                continue # Si una línea falla, saltamos a la siguiente
            
        pdf.output(pdf_name)
        
        await update.message.reply_document(
            document=open(pdf_name, 'rb'), 
            caption=f"📊 *Auditoría Finalizada para {ip}*\n\nSe han analizado vulnerabilidades persistentes, de DOM y servicios expuestos."
        )
        os.remove(pdf_name)
        
    except Exception as e:
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
    app = Application.builder().token(TOKEN_TELEGRAM).read_timeout(30).write_timeout(30).build()

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
