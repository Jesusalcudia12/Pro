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

# Estados para la interactividad (ConversationHandler)
ESPERANDO_SCAN, ESPERANDO_LOGINS, ESPERANDO_EXPLOIT, ESPERANDO_BUGS, ESPERANDO_WEB = range(5)

if not os.path.exists(LEAKS_DIR):
    os.makedirs(LEAKS_DIR)

# --- CLASE PDF ---
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'ZENITH TITAN v73.0 - REPORT', 0, 1, 'C')
        self.ln(10)

def generate_pdf(filename, content, title, admin_highlight=False):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, title, 0, 1)
    pdf.ln(5)
    pdf.set_font("Arial", size=10)
    
    admin_keys = ["admin", "root", "manager", "dashboard", "wp-login", "panel", "config"]
    
    for line in content:
        if admin_highlight and any(k in line.lower() for k in admin_keys):
            pdf.set_text_color(255, 0, 0)
            pdf.multi_cell(0, 8, txt=f"[!] {line}")
        else:
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(0, 8, txt=line)
    pdf.output(filename)

# --- INICIO DE CONVERSACIONES ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "👑 *Zenith Titan v73.0 ACTIVO*\n\n"
        "start - Iniciar Zenith Titan v73.0\n"
        "status - Verificar hilos, archivos y estado de APIs\n"
        "scan - Mapeo de Red: Dominios asociados e IPs en vivo\n"
        "logins - Web Scraper: Leaks frescos (URL+Correo+Pass)\n"
        "exploit - Exploit Engine: Buscar CVEs y códigos PoC\n"
        "find_bugs - Auditoría Pro: Escaneo Nmap + Reporte PDF\n"
        "search_web - Búsqueda rápida en combos locales (.txt)\n"
        "upload_combo - Subir archivos de texto a la base"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    archivos = len([f for f in os.listdir(LEAKS_DIR) if f.endswith('.txt')])
    await update.message.reply_text(f"📊 *Estado:* \n• APIs: Online (Netlas)\n• Archivos en Base: {archivos}\n• Hilos: Optimizados v73")

# --- PROCESAMIENTO INTERACTIVO ---

async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🌐 *Mapeo de Red:* Inserta la URL o Dominio:")
    return ESPERANDO_SCAN

async def cmd_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔓 *Web Scraper:* Inserta la URL/Dominio para buscar leaks:")
    return ESPERANDO_LOGINS

async def cmd_exploit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("💀 *Exploit Engine:* Inserta el nombre del software o CVE (ej: Apache 2.4):")
    return ESPERANDO_EXPLOIT

async def cmd_find_bugs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🎯 *Auditoría Pro:* Inserta la dirección IP:")
    return ESPERANDO_BUGS

async def cmd_search_web(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📂 *Búsqueda Local:* Inserta el término para buscar en los combos .txt:")
    return ESPERANDO_WEB

# --- LÓGICA DE EJECUCIÓN ---

async def proc_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = update.message.text
    headers = {'X-API-Key': API_NETLAS}
    url = f"https://app.netlas.io/api/domains/?q=domain:*.{target}"
    try:
        res = requests.get(url, headers=headers).json()
        data = [f"{i['data']['domain']} -> {i['data'].get('ip', 'N/A')}" for i in res.get('items', [])]
        pdf_name = f"scan_{target}.pdf"
        generate_pdf(pdf_name, data, f"Mapeo de Red: {target}")
        await update.message.reply_document(document=open(pdf_name, 'rb'), caption=f"✅ Mapeo de {target} finalizado.")
        os.remove(pdf_name)
    except: await update.message.reply_text("❌ Error en Netlas.")
    return ConversationHandler.END

async def proc_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.message.text.lower()
    encontrados = []
    for archivo in os.listdir(LEAKS_DIR):
        if archivo.endswith(".txt"):
            with open(os.path.join(LEAKS_DIR, archivo), 'r', errors='ignore') as f:
                for line in f:
                    if query in line.lower(): encontrados.append(line.strip())
    if encontrados:
        pdf_name = f"leaks_{query}.pdf"
        generate_pdf(pdf_name, encontrados, f"Leaks Detectados: {query}", admin_highlight=True)
        await update.message.reply_document(document=open(pdf_name, 'rb'), caption=f"🔥 Se hallaron {len(encontrados)} leaks.")
        os.remove(pdf_name)
    else: await update.message.reply_text("✅ No se hallaron resultados.")
    return ConversationHandler.END

async def proc_exploit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.message.text
    url = f"https://sploitus.com/search?query={urllib.parse.quote(query)}"
    await update.message.reply_text(f"💀 *PoCs y Exploits encontrados:* [Ver en Sploitus]({url})", parse_mode="Markdown")
    return ConversationHandler.END

async def proc_find_bugs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip = update.message.text
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-F --script vuln')
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    results.append(f"Puerto {port}: {nm[host][proto][port]['state']} - {nm[host][proto][port].get('name')}")
        pdf_name = f"bugs_{ip}.pdf"
        generate_pdf(pdf_name, results, f"Auditoria de Vulnerabilidades: {ip}")
        await update.message.reply_document(document=open(pdf_name, 'rb'), caption=f"📊 Auditoría para {ip} terminada.")
        os.remove(pdf_name)
    except: await update.message.reply_text("❌ Error en Nmap.")
    return ConversationHandler.END

async def proc_search_web(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # En este comando usamos la lógica de combos locales según tu lista
    return await proc_logins(update, context)

async def upload_combo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📩 Por favor, adjunta el archivo .txt para subirlo a la base.")

async def handle_docs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if doc.file_name.endswith(".txt"):
        path = os.path.join(LEAKS_DIR, doc.file_name)
        new_file = await context.bot.get_file(doc.file_id)
        await new_file.download_to_drive(path)
        await update.message.reply_text(f"✅ Combo `{doc.file_name}` subido con éxito.")

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
            ESPERANDO_WEB: [MessageHandler(filters.TEXT & ~filters.COMMAND, proc_search_web)],
        },
        fallbacks=[CommandHandler("cancel", lambda u,c: ConversationHandler.END)]
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("upload_combo", upload_combo))
    app.add_handler(conv_handler)
    app.add_handler(MessageHandler(filters.Document.ALL, handle_docs))
    
    print("Zenith Titan v73.0 Corriendo...")
    app.run_polling()
