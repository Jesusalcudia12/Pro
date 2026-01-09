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
    await update.message.reply_text(f"🛰 *Escaneando infraestructura de:* `{target}`...")
    headers = {'X-API-Key': API_NETLAS}
    url = f"https://app.netlas.io/api/domains/?q=domain:*.{target}"
    try:
        res = requests.get(url, headers=headers).json()
        items = res.get('items', [])
        
        if not items:
            await update.message.reply_text("❌ No se encontraron resultados en Netlas.")
            return ConversationHandler.END

        mensaje = f"🌐 *RUTAS E IPS HALLADAS PARA:* `{target}`\n\n"
        for i in items[:30]:
            domain = i['data'].get('domain', 'N/A')
            ip = i['data'].get('ip', i['data'].get('a', 'Desconocida'))
            mensaje += f"📍 `{domain}`\n└─ 💻 IP: `{ip}`\n\n"
        
        if len(mensaje) > 4096:
            for x in range(0, len(mensaje), 4096):
                await update.message.reply_text(mensaje[x:x+4096], parse_mode="Markdown")
        else:
            await update.message.reply_text(mensaje, parse_mode="Markdown")
    except: await update.message.reply_text("❌ Error al conectar con Netlas.")
    return ConversationHandler.END

async def cmd_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔓 *Deep Web Scraper:* Inserta la URL o dominio de la empresa:")
    return ESPERANDO_LOGINS

async def proc_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.message.text.strip().lower()
    await update.message.reply_text(f"🔎 Buscando accesos para `{query}`...")
    
    encontrados = []
    admin_tags = ["admin", "root", "panel", "login", "config", "dashboard"]
    
    for archivo in os.listdir(LEAKS_DIR):
        if archivo.endswith(".txt"):
            with open(os.path.join(LEAKS_DIR, archivo), 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if query in line.lower():
                        encontrados.append(line.strip())
                    if len(encontrados) >= 40: break
        if len(encontrados) >= 40: break

    if encontrados:
        res_msg = f"🔥 *CREDENCIALES HALLADAS PARA:* `{query}`\n"
        res_msg += "Formato: `URL : CORREO : PASS`\n\n"
        for res in encontrados:
            es_admin = "🚨 [ADMIN] " if any(tag in res.lower() for tag in admin_tags) else "👤 "
            res_msg += f"{es_admin}`{res}`\n\n"
        
        if len(res_msg) > 4096:
            for x in range(0, len(res_msg), 4096):
                await update.message.reply_text(res_msg[x:x+4096], parse_mode="Markdown")
        else:
            await update.message.reply_text(res_msg, parse_mode="Markdown")
    else:
        await update.message.reply_text(f"✅ No se hallaron credenciales para `{query}`.")
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
