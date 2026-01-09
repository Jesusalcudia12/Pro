import logging
import os
import re
import httpx
import requests
import nmap
import urllib.parse
from telegram import Update
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

# --- COMANDOS DE INICIO Y ESTADO ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "👑 *Zenith Titan v73.0 ACTIVO*\n\n"
        "🟢 `/scan` - Mapeo de subdominios y archivos expuestos\n"
        "🛡️ `/check_security` - Analizar cabeceras (CSP/XFO/HSTS)\n"
        "🔓 `/logins` - Buscar credenciales en bases de datos locales\n"
        "🌐 `/search_web` - Búsqueda de filtraciones en la web (Dorks)\n"
        "🎯 `/find_bugs` - Auditoría técnica Nmap (Genera PDF)\n"
        "💀 `/exploit` - Buscar PoCs de vulnerabilidades (CVE)\n"
        "📊 `/status` - Estado del sistema\n"
        "📩 `/upload_combo` - Subir base de datos .txt"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    archivos = len([f for f in os.listdir(LEAKS_DIR) if f.endswith('.txt')])
    await update.message.reply_text(f"📊 *Estado:* \n• APIs: Online\n• Bases Locales: {archivos} archivos\n• Motor: Titan v73.0")

# --- LÓGICA DE ESCANEO (NETLAS) ---

async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🌐 *Mapeo de Red:* Inserta el dominio:")
    return ESPERANDO_SCAN

async def proc_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = update.message.text.strip()
    await update.message.reply_text(f"🛰 *Escaneando infraestructura:* `{target}`...")
    headers = {'X-API-Key': API_NETLAS}
    url = f"https://app.netlas.io/api/domains/?q=domain:*.{target}"
    try:
        res = requests.get(url, headers=headers).json()
        items = res.get('items', [])
        mensaje = f"🌐 *INFRAESTRUCTURA:* `{target}`\n\n"
        for i in items[:10]:
            mensaje += f"📍 `{i['data'].get('domain')}` | IP: `{i['data'].get('ip')}`\n"
        await update.message.reply_text(mensaje or "❌ Sin resultados.", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")
    return ConversationHandler.END

# --- LÓGICA DE CREDENCIALES LOCALES Y WEB ---

async def cmd_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔓 *Búsqueda Local:* Inserta el correo o dominio:")
    return ESPERANDO_LOGINS

async def proc_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.message.text.strip().lower()
    encontrados = []
    for archivo in os.listdir(LEAKS_DIR):
        if archivo.endswith(".txt"):
            with open(os.path.join(LEAKS_DIR, archivo), 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if query in line.lower(): encontrados.append(line.strip())
                    if len(encontrados) >= 20: break
    res = f"🔥 *LEAKS LOCALES:* `{query}`\n\n" + "\n".join([f"🔓 `{r}`" for r in encontrados])
    await update.message.reply_text(res[:4096] if encontrados else "✅ Sin resultados locales.", parse_mode="Markdown")
    return ConversationHandler.END

async def cmd_search_web(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🌐 *Búsqueda Web:* Inserta el objetivo para generar Dorks:")
    return ESPERANDO_WEB

async def proc_search_web(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = update.message.text.strip()
    dork = f"site:pastebin.com OR site:github.com \"{target}\" password"
    link = f"https://www.google.com/search?q={urllib.parse.quote(dork)}"
    await update.message.reply_text(f"🔎 *Dork Generado para {target}:*\n\n[Haz clic aquí para ver filtraciones web]({link})", parse_mode="Markdown")
    return ConversationHandler.END

# --- LÓGICA DE EXPLOITS Y SEGURIDAD ---

async def cmd_exploit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("💀 *Exploit Finder:* Inserta el nombre del software o CVE (ej: BlueKeep):")
    return ESPERANDO_EXPLOIT

async def proc_exploit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.message.text.strip()
    url = f"https://sploitus.com/search?query={urllib.parse.quote(query)}"
    await update.message.reply_text(f"💀 *PoCs hallados para {query}:*\n\n[Ver resultados en Sploitus]({url})", parse_mode="Markdown")
    return ConversationHandler.END

async def check_security(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = context.args[0] if context.args else None
    if not target:
        await update.message.reply_text("❌ Uso: `/check_security dominio.com`")
        return
    url = f"https://{target}" if not target.startswith("http") else target
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        try:
            r = await client.get(url)
            h = r.headers
            res = (f"🛡️ *SEGURIDAD:* {target}\n\n"
                   f"🔹 CSP: `{h.get('Content-Security-Policy', '⚠️ Falta')[:30]}...`\n"
                   f"🔹 X-Frame: `{h.get('X-Frame-Options', '⚠️ Falta')}`\n"
                   f"🔹 HSTS: `{h.get('Strict-Transport-Security', '⚠️ Falta')}`")
            await update.message.reply_text(res, parse_mode="Markdown")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {e}")

# --- LÓGICA DE AUDITORÍA (NMAP) ---

async def cmd_find_bugs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🎯 *Auditoría:* Inserta la IP:")
    return ESPERANDO_BUGS

async def proc_find_bugs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip = update.message.text.strip()
    await update.message.reply_text(f"⏳ Analizando {ip}...")
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-sV --script http-dombased-xss')
        pdf_name = f"Audit_{ip}.pdf"
        pdf = PDF()
        pdf.add_page()
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, txt=str(nm[ip]) if ip in nm.all_hosts() else "No host found")
        pdf.output(pdf_name)
        await update.message.reply_document(document=open(pdf_name, 'rb'))
        os.remove(pdf_name)
    except Exception as e:
        await update.message.reply_text(f"❌ Error Nmap: {e}")
    return ConversationHandler.END

# --- GESTIÓN DE ARCHIVOS ---

async def handle_docs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if doc.file_name.endswith(".txt"):
        path = os.path.join(LEAKS_DIR, doc.file_name)
        file = await context.bot.get_file(doc.file_id)
        await file.download_to_drive(path)
        await update.message.reply_text(f"✅ Base actualizada: `{doc.file_name}`")

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
    app.add_handler(CommandHandler("check_security", check_security))
    app.add_handler(conv_handler)
    app.add_handler(MessageHandler(filters.Document.ALL, handle_docs))
    
    print("Zenith Titan v73.0 Full Running...")
    app.run_polling()
