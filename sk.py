import logging
import os
import requests
import nmap
import urllib.parse
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# --- CONFIGURACIÓN ---
TOKEN_TELEGRAM = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
API_NETLAS = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
LEAKS_DIR = "leaks/"

if not os.path.exists(LEAKS_DIR):
    os.makedirs(LEAKS_DIR)

# --- COMANDOS ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "👑 *Zenith Titan v73.0 ACTIVO*\n\n"
        "🟢 `/scan` - Mapeo de Red (Netlas)\n"
        "📊 `/status` - Estado del sistema\n"
        "🔓 `/logins` - Buscar leaks en base local\n"
        "🌐 `/search_web` - Google Dorks (Arquivos/Admin)\n"
        "💀 `/exploit` - Buscar PoCs de CVEs\n"
        "🎯 `/find_bugs` - Escaneo Nmap Vuln\n"
        "📩 *Envía un .txt* para subir a la base de combos."
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    archivos = len([f for f in os.listdir(LEAKS_DIR) if f.endswith('.txt')])
    await update.message.reply_text(f"📊 *Estado:* \n• APIs: Online\n• Archivos en Base: {archivos}\n• Motor: Titan v73")

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await update.message.reply_text("Uso: /scan dominio.com")
    
    target = context.args[0]
    await update.message.reply_text(f"🛰 *Consultando Netlas para:* {target}")
    headers = {'X-API-Key': API_NETLAS}
    url = f"https://app.netlas.io/api/domains/?q=domain:*.{target}"
    
    try:
        res = requests.get(url, headers=headers).json()
        items = res.get('items', [])
        results = "\n".join([f"• {i['data']['domain']} ➔ {i['data'].get('ip', 'N/A')}" for i in items[:15]])
        await update.message.reply_text(f"🌐 *Subdominios Hallados:*\n\n{results or 'Sin resultados.'}")
    except:
        await update.message.reply_text("❌ Error al conectar con Netlas.")

async def search_web(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await update.message.reply_text("Uso: /search_web dominio.com")
    
    target = context.args[0]
    dorks = {
        "📂 Docs": f"site:{target} filetype:pdf OR filetype:xlsx OR filetype:env",
        "🔑 Admin": f"site:{target} inurl:admin OR inurl:login",
        "⚠️ Index": f"site:{target} intitle:\"index of /\""
    }
    reporte = f"🔍 *Dorks para {target}:*\n\n"
    for k, v in dorks.items():
        link = f"https://www.google.com/search?q={urllib.parse.quote(v)}"
        reporte += f"{k}: [Ver en Google]({link})\n"
    await update.message.reply_text(reporte, parse_mode="Markdown", disable_web_page_preview=True)

async def logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await update.message.reply_text("Uso: /logins url/correo")
    
    query = context.args[0].lower()
    await update.message.reply_text(f"🔓 *Buscando en base local para:* {query}")
    encontrados = []
    
    for archivo in os.listdir(LEAKS_DIR):
        if archivo.endswith(".txt"):
            with open(os.path.join(LEAKS_DIR, archivo), 'r', errors='ignore') as f:
                for line in f:
                    if query in line.lower():
                        encontrados.append(line.strip())
                        if len(encontrados) >= 10: break
        if len(encontrados) >= 10: break
    
    res = "\n".join([f"`{e}`" for e in encontrados])
    await update.message.reply_text(f"🔥 *Resultados:*\n{res or 'Cero coincidencias.'}", parse_mode="Markdown")

async def find_bugs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await update.message.reply_text("Uso: /find_bugs <IP>")
    
    ip = context.args[0]
    await update.message.reply_text(f"🎯 *Escaneando vulnerabilidades en {ip}...*")
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-F --script vuln') # Escaneo rápido de vulns
        msg = f"📊 *Reporte para {ip}:*\n"
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    msg += f"• Puerto {port}: {nm[host][proto][port]['state']}\n"
        await update.message.reply_text(msg)
    except:
        await update.message.reply_text("❌ Error al ejecutar Nmap.")

async def handle_docs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if doc.file_name.endswith(".txt"):
        path = os.path.join(LEAKS_DIR, doc.file_name)
        file = await context.bot.get_file(doc.file_id)
        await file.download_to_drive(path)
        await update.message.reply_text(f"✅ Combo `{doc.file_name}` añadido a la base.")

# --- MAIN ---
if __name__ == '__main__':
    app = Application.builder().token(TOKEN_TELEGRAM).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CommandHandler("search_web", search_web))
    app.add_handler(CommandHandler("logins", logins))
    app.add_handler(CommandHandler("find_bugs", find_bugs))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_docs))
    
    print("Zenith Titan Online...")
    app.run_polling()
