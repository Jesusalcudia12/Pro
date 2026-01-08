import telebot
from telebot import types
import netlas, requests, os, sqlite3, subprocess, json, glob, time, re, socket
from fpdf import FPDF
from datetime import datetime
from urllib.parse import quote, urlparse

# ==========================================
# CONFIGURACIÓN DE IDENTIDAD Y SEGURIDAD
# ==========================================
TELEGRAM_TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
TELEGRAM_CHAT_ID = 6280594821 
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"

# Optimización: 50 hilos y manejo de concurrencia
bot = telebot.TeleBot(TELEGRAM_TOKEN, threaded=True, num_threads=50)
n_api = netlas.Netlas(api_key=NETLAS_API_KEY)

# ==========================================
# MOTOR DE BASE DE DATOS
# ==========================================
class DatabaseManager:
    def __init__(self, db_name='zenith_titan.db'):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.setup()

    def setup(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS objetivos 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, tipo TEXT, fecha TEXT)''')
        self.conn.commit()

    def registrar(self, target, tipo):
        fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            self.cursor.execute("INSERT INTO objetivos (target, tipo, fecha) VALUES (?, ?, ?)", (target, tipo, fecha))
            self.conn.commit()
        except: pass

db = DatabaseManager()

# ==========================================
# MOTOR DE REPORTES PDF
# ==========================================
class ZenithReport(FPDF):
    def header(self):
        self.set_fill_color(20, 20, 20)
        self.rect(0, 0, 210, 40, 'F')
        self.set_font('Arial', 'B', 22)
        self.set_text_color(255, 255, 255)
        self.cell(0, 20, 'ZENITH TITAN AUDIT REPORT', 0, 1, 'C')
        self.ln(20)

def generar_pdf(target, nmap_data):
    pdf = ZenithReport()
    pdf.add_page()
    pdf.set_font("Courier", 'B', 12)
    pdf.cell(0, 10, f"TARGET: {target}", ln=True)
    pdf.ln(5)
    pdf.set_font("Courier", size=9)
    pdf.multi_cell(0, 5, txt=nmap_data)
    path = f"AUDIT_{target.replace('.', '_')}.pdf"
    pdf.output(path)
    return path

# ==========================================
# MANEJADORES DE COMANDOS
# ==========================================

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    if message.chat.id != TELEGRAM_CHAT_ID: return
    text = (
        "🚀 **ZENITH TITAN v76.0 OMNI-CORE**\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🛰 `/scan` - Mapeo de Red (Dominios e IPs)\n"
        "🔓 `/logins` - Búsqueda de Leaks Reales (Dorks)\n"
        "💀 `/exploit` - Buscador de Exploits CVE\n"
        "🎯 `/find_bugs` - Auditoría Nmap + Reporte PDF\n"
        "📂 `/scan_url` - Buscar en base de datos local\n"
        "📩 `/upload_combo` - Subir archivos .txt\n"
        "📊 `/status` - Estado del sistema y archivos\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Seleccione una opción del menú:"
    )
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add('/scan', '/logins', '/exploit', '/find_bugs', '/scan_url', '/status')
    bot.send_message(message.chat.id, text, parse_mode="Markdown", reply_markup=markup)

# 1. SCAN (Infraestructura)
@bot.message_handler(commands=['scan'])
def cmd_scan(message):
    msg = bot.send_message(message.chat.id, "🌐 Ingrese el dominio para mapear:")
    bot.register_next_step_handler(msg, process_scan)

def process_scan(message):
    target = message.text.strip().lower()
    bot.send_message(message.chat.id, "📡 Consultando Netlas y resolviendo IPs...")
    try:
        res = n_api.query(query=f"domain:*.{target}", datatype="domain")
        items = res.get('items', [])[:20]
        out = f"🛰 **INFRAESTRUCTURA: {target}**\n\n"
        for i in items:
            d = i['data']['domain']
            try: ip = socket.gethostbyname(d); out += f"• `{d}` ➔ `{ip}`\n"
            except: out += f"• `{d}` ➔ `[No IP]`\n"
        bot.send_message(message.chat.id, out, parse_mode="Markdown")
        db.registrar(target, "SCAN")
    except: bot.send_message(message.chat.id, "❌ Error en la API.")

# 2. LOGINS (Inteligencia de Filtraciones)
@bot.message_handler(commands=['logins'])
def cmd_logins(message):
    msg = bot.send_message(message.chat.id, "🔓 Ingrese dominio para rastrear leaks reales:")
    bot.register_next_step_handler(msg, process_logins)

def process_logins(message):
    target = message.text.strip().lower()
    dork = quote(f'site:pastebin.com OR site:github.com "{target}" password')
    res = (f"☣️ **INTELIGENCIA WEB: {target}**\n\n"
           f"📂 [CLICK AQUÍ PARA VER LEAKS REALES](https://www.google.com/search?q={dork})\n\n"
           "💡 *Usa /upload_combo si descargas un archivo .txt*")
    bot.send_message(message.chat.id, res, parse_mode="Markdown", disable_web_page_preview=True)

# 3. EXPLOIT (CVE)
@bot.message_handler(commands=['exploit'])
def cmd_exploit(message):
    msg = bot.send_message(message.chat.id, "💀 ¿Qué servicio/tecnología buscas?")
    bot.register_next_step_handler(msg, process_exploit)

def process_exploit(message):
    tech = message.text.strip()
    try:
        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(tech)}").json()
        vulns = r.get('vulnerabilities', [])[:5]
        out = f"☢️ **EXPLOITS: {tech}**\n\n"
        for v in vulns:
            id_cve = v['cve']['id']
            out += f"• {id_cve} ➔ [Exploit-DB](https://www.exploit-db.com/search?cve={id_cve[4:]})\n"
        bot.send_message(message.chat.id, out, parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "❌ Sin resultados.")

# 4. FIND_BUGS (Nmap Persistente)
@bot.message_handler(commands=['find_bugs'])
def cmd_bugs(message):
    msg = bot.send_message(message.chat.id, "🎯 Ingrese IP o Dominio para Auditoría Profunda:")
    bot.register_next_step_handler(msg, process_bugs)

def process_bugs(message):
    target = message.text.strip().lower()
    bot.send_message(message.chat.id, "🚀 **Auditando...** (Tiempo estimado: 2-5 min). No cierres el bot.")
    try:
        # T4 para velocidad, -Pn para ignorar ping, --script=vuln para bugs
        nmap_cmd = ["nmap", "-F", "-Pn", "--script=vuln", "--max-retries", "3", "-T4", target]
        output = subprocess.check_output(nmap_cmd, timeout=600, text=True)
        pdf_path = generar_pdf(target, output)
        with open(pdf_path, "rb") as f:
            bot.send_document(message.chat.id, f, caption=f"🏆 Auditoría: {target}")
        os.remove(pdf_path)
    except Exception as e:
        bot.send_message(message.chat.id, f"⚠️ Error o Tiempo Agotado. Reintentando básico...\n`{str(e)[:100]}`")
        try:
            output = subprocess.check_output(["nmap", "-F", target], timeout=120, text=True)
            bot.send_message(message.chat.id, f"✅ Escaneo rápido:\n`{output}`")
        except: bot.send_message(message.chat.id, "❌ Objetivo inalcanzable.")

# 5. SCAN_URL (Búsqueda Local)
@bot.message_handler(commands=['scan_url'])
def cmd_local(message):
    msg = bot.send_message(message.chat.id, "📂 Palabra a buscar en archivos locales:")
    bot.register_next_step_handler(msg, process_local)

def process_local(message):
    query = message.text.strip().lower()
    matches = []
    for f in glob.glob("combos/*.txt"):
        with open(f, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                if query in line.lower():
                    matches.append(line.strip())
                if len(matches) >= 20: break
    if matches:
        bot.send_message(message.chat.id, "🔑 **ENCONTRADO:**\n\n" + "\n".join([f"`{m}`" for m in matches]), parse_mode="Markdown")
    else: bot.send_message(message.chat.id, "❌ Sin coincidencias.")

# 6. STATUS Y UPLOAD
@bot.message_handler(commands=['status'])
def cmd_status(message):
    num = len(glob.glob("combos/*.txt")) if os.path.exists("combos") else 0
    bot.send_message(message.chat.id, f"📊 **ESTADO:** ONLINE\n• Hilos: 50\n• Archivos en Base: {num} .txt\n• API Netlas: Conectada")

@bot.message_handler(commands=['upload_combo'])
def cmd_upload(message):
    bot.send_message(message.chat.id, "📩 Envíame un archivo .txt para la base.")

@bot.message_handler(content_types=['document'])
def handle_docs(message):
    if message.document.file_name.endswith('.txt'):
        f = bot.get_file(message.document.file_id)
        d = bot.download_file(f.file_path)
        if not os.path.exists("combos"): os.makedirs("combos")
        with open(f"combos/{message.document.file_name}", "wb") as file: file.write(d)
        bot.reply_to(message, "✅ Base de datos alimentada.")

if __name__ == "__main__":
    print("🚀 ZENITH TITAN v76.0 - OMNI-CORE READY")
    bot.infinity_polling(skip_pending=True)
