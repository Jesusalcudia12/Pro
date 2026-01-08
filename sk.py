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

# --- CLASE PDF PROFESIONAL ---
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
        # Lógica de resaltado administrativo en rojo
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
        "🟢 `/scan` - Mapeo de Red e IPs\n"
        "📊 `/status` - Estado del sistema\n"
        "🔓 `/logins` - Leaks Profundos (User:Pass)\n"
        "💀 `/exploit` - Buscar PoCs de CVEs\n"
        "🎯 `/find_bugs` - Auditoría Pro PDF\n"
        "🌐 `/search_web` - Búsqueda en Combos\n"
        "📩 `/upload_combo` - Subir base de datos"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    archivos = len([f for f in os.listdir(LEAKS_DIR) if f.endswith('.txt')])
    await update.message.reply_text(f"📊 *Estado:* \n• APIs: Online (Netlas)\n• Archivos en Base: {archivos}\n• Motor: Titan v73.0 Deep Scan")

# --- PROCESAMIENTO INTERACTIVO (MEJORADO) ---

async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🌐 *Mapeo:* Inserta la URL o Dominio para extraer IPs:")
    return ESPERANDO_SCAN

async def cmd_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔓 *Extracción Profunda:* Inserta la URL o ruta del panel para buscar correos y claves:")
    return ESPERANDO_LOGINS

# --- LÓGICA DE EJECUCIÓN MEJORADA ---

async def proc_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = update.message.text.strip()
    headers = {'X-API-Key': API_NETLAS}
    url = f"https://app.netlas.io/api/domains/?q=domain:*.{target}"
    try:
        res = requests.get(url, headers=headers).json()
        items = res.get('items', [])
        # Mejora: Busca IP en registros A o en el campo ip directo
        data = []
        for i in items:
            domain = i['data'].get('domain', 'N/A')
            ip = i['data'].get('ip', i['data'].get('a', 'No detectada'))
            data.append(f"{domain} | IP: {ip}")
            
        pdf_name = f"scan_{target}.pdf"
        generate_pdf(pdf_name, data, f"Mapeo de Red e IPs: {target}")
        await update.message.reply_document(document=open(pdf_name, 'rb'), caption=f"✅ Mapeo de {target} finalizado.")
        os.remove(pdf_name)
    except: await update.message.reply_text("❌ Error en Netlas o sin resultados.")
    return ConversationHandler.END

async def proc_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.message.text.strip().lower()
    await update.message.reply_text(f"🔍 Buscando credenciales de usuarios y admins para: `{query}`...")
    
    encontrados = []
    # Búsqueda profunda en todos los archivos de la carpeta leaks
    for archivo in os.listdir(LEAKS_DIR):
        if archivo.endswith(".txt"):
            with open(os.path.join(LEAKS_DIR, archivo), 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if query in line.lower():
                        encontrados.append(line.strip())
    
    if encontrados:
        pdf_name = f"leaks_{query.replace('/', '_')}.pdf"
        generate_pdf(pdf_name, encontrados, f"Extracción de Credenciales: {query}", admin_highlight=True)
        await update.message.reply_document(
            document=open(pdf_name, 'rb'), 
            caption=f"🔥 ÉXITO: Se extrajeron {len(encontrados)} registros (User:Pass)."
        )
        os.remove(pdf_name)
    else:
        await update.message.reply_text("✅ No se hallaron credenciales en lo profundo de esa URL.")
    return ConversationHandler.END

# --- COMANDOS RESTANTES (MANTENIDOS) ---

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

async def proc_find_bugs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip = update.message.text
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-F --script vuln')
        results = [f"Puerto {p}: {nm[host][proto][p]['state']}" for host in nm.all_hosts() for proto in nm[host].all_protocols() for p in nm[host][proto]]
        pdf_name = f"bugs_{ip}.pdf"
        generate_pdf(pdf_name, results, f"Auditoría Pro: {ip}")
        await update.message.reply_document(document=open(pdf_name, 'rb'), caption=f"📊 Reporte de vulnerabilidades para {ip}.")
        os.remove(pdf_name)
    except: await update.message.reply_text("❌ Error en escaneo.")
    return ConversationHandler.END

async def cmd_search_web(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📂 *Búsqueda Local:* Inserta término:")
    return ESPERANDO_WEB

async def upload_combo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📩 Envía el archivo .txt con los combos para guardarlos.")

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
    
    print("Zenith Titan v73.0 con Extracción Profunda Online...")
    app.run_polling()
