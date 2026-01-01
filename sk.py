import telebot
from telebot import types
import netlas, requests, os, sqlite3, subprocess, socket, logging, json
from fpdf import FPDF
from datetime import datetime, timedelta
from urllib.parse import quote

# === CONFIGURACIÓN DE IDENTIDAD Y SEGURIDAD ===
TELEGRAM_TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
TELEGRAM_CHAT_ID = 6280594821 
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"

# APIs de Terceros para datos reales (PII)
DEHASHED_API_KEY = "TU_API_KEY"
DEHASHED_USER = "TU_EMAIL"

# Configuración Financiera
MI_BILLETERA_USDT = "TWzf9VJmr2mhq5H8Xa3bLhbb8dwmWdG9B7I"
PRECIO_BASE = "350.00 USDT"

# Inicialización de servicios
bot = telebot.TeleBot(TELEGRAM_TOKEN)
n_api = netlas.Netlas(api_key=NETLAS_API_KEY)

# Configuración de Logs de Auditoría
logging.basicConfig(
    filename='zenith_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# === MOTOR DE BASE DE DATOS PROFESIONAL ===
class DatabaseManager:
    def __init__(self, db_name='zenith_titan.db'):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS objetivos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            tipo_scan TEXT,
            fecha TEXT,
            estado_pago INTEGER DEFAULT 0,
            monto TEXT
        )''')
        self.conn.commit()

    def registrar_operacion(self, target, tipo):
        cursor = self.conn.cursor()
        fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("INSERT INTO objetivos (target, tipo_scan, fecha, monto) VALUES (?, ?, ?, ?)",
                       (target, tipo, fecha, PRECIO_BASE))
        self.conn.commit()
        logging.info(f"Operación registrada: {tipo} sobre {target}")

db = DatabaseManager()

# === MOTOR DE REPORTES PDF (Zenith Engine) ===
class ZenithReport(FPDF):
    def header(self):
        self.set_fill_color(15, 15, 15)
        self.rect(0, 0, 210, 40, 'F')
        self.set_font('Arial', 'B', 24)
        self.set_text_color(255, 255, 255)
        self.cell(0, 20, 'ZENITH TITAN SYSTEMS', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 5, 'Strategic Cyber-Intelligence Division', 0, 1, 'C')
        self.ln(25)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f'ID de Auditoría: {os.urandom(4).hex().upper()} | Página {self.page_no()}', 0, 0, 'C')

def generar_pdf_profesional(target, contenido, titulo_doc):
    pdf = ZenithReport()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(200, 0, 0)
    pdf.cell(0, 10, f"REPORTE: {titulo_doc}", ln=True)
    pdf.ln(5)
    
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, f"Objetivo: {target}", ln=True)
    pdf.cell(0, 8, f"Fecha de Emisión: {datetime.now().strftime('%d/%m/%Y %H:%M')}", ln=True)
    pdf.ln(10)
    
    pdf.set_font("Arial", '', 10)
    pdf.multi_cell(0, 7, txt=contenido, border=1)
    
    pdf.ln(15)
    pdf.set_fill_color(245, 245, 245)
    pdf.rect(10, pdf.get_y(), 190, 40, 'F')
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "INFORMACIÓN FINANCIERA DE SERVICIO", ln=True)
    pdf.set_font("Arial", '', 11)
    pdf.cell(0, 7, f"Costo Total: {PRECIO_BASE}", ln=True)
    pdf.cell(0, 7, f"Red: USDT TRC20 (Tron Network)", ln=True)
    pdf.cell(0, 7, f"Wallet: {MI_BILLETERA_USDT}", ln=True)
    
    path = f"Zenith_{titulo_doc}_{target.replace('.', '_')}.pdf"
    pdf.output(path)
    return path

# === FUNCIONES DE RECONOCIMIENTO REAL ===
# --- FUNCIÓN DE BÚSQUEDA REAL EN LA NVD (NIST) ---
def buscar_cves_reales(tecnologia):
    # La API de NIST permite buscar vulnerabilidades por palabras clave
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tecnologia}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            vulnerabilidades = data.get('vulnerabilities', [])
            return vulnerabilidades
        return None
    except Exception as e:
        print(f"Error consultando NIST: {e}")
        return None
        
def exec_nmap_pro(target, mode="standard"):
    # Comandos reales del sistema
    if mode == "deep":
        cmd = ["nmap", "-sV", "-sC", "-T4", "-Pn", target]
    else:
        cmd = ["nmap", "-F", target]
    
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return process.stdout if process.stdout else "No se detectaron puertos abiertos."
    except Exception as e:
        return f"Error en ejecución de Nmap: {str(e)}"

def get_pii_data(query):
    # Conexión real con DeHashed para obtener PII
    url = f"https://api.dehashed.com/protocol/v1/get?query={query}"
    try:
        r = requests.get(url, auth=(DEHASHED_USER, DEHASHED_API_KEY), headers={'Accept': 'application/json'})
        if r.status_code == 200:
            entries = r.json().get('entries', [])
            return entries
        return []
    except:
        return []

# === HANDLERS DE COMANDOS (SUITE COMPLETA) ===

@bot.message_handler(commands=['start'])
def welcome(message):
    if message.from_user.id != TELEGRAM_CHAT_ID: return
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add('/leak', '/reporte', '/scan_url', '/port_scan', '/exploit_deep', '/status')
    bot.send_message(message.chat.id, "👑 *ZENITH TITAN OMEGA v46.0*\nSistema Cargado. Esperando Instrucciones.", parse_mode="Markdown", reply_markup=markup)

@bot.message_handler(commands=['leak'])
def leak_command(message):
    msg = bot.send_message(message.chat.id, "📧 Ingrese Correo o Nombre para extracción PII Real:")
    bot.register_next_step_handler(msg, process_leak_logic)

def process_leak_logic(message):
    target = message.text
    bot.send_message(message.chat.id, "📡 Accediendo a brechas de datos... Esto puede tardar.")
    
    data = get_pii_data(target)
    content = ""
    if data:
        for i, entry in enumerate(data[:15]):
            content += f"[{i+1}] NOMBRE: {entry.get('name', 'N/A')}\n"
            content += f"    TEL: {entry.get('phone', 'N/A')}\n"
            content += f"    DIR: {entry.get('address', 'N/A')}\n"
            content += f"    PASS: {entry.get('password', 'N/A')}\n"
            content += f"    DB: {entry.get('database_name', 'N/A')}\n"
            content += "-"*40 + "\n"
    else:
        content = "No se encontraron registros vinculados en las bases de datos de brechas actuales."

    pdf_path = generar_pdf_profesional(target, content, "EXPOSICION_IDENTIDAD")
    with open(pdf_path, "rb") as f:
        bot.send_document(message.chat.id, f, caption=f"✅ Datos Reales extraídos para {target}")
    os.remove(pdf_path)
    db.registrar_operacion(target, "LEAK_PII")

@bot.message_handler(commands=['port_scan'])
def port_scan_cmd(message):
    msg = bot.send_message(message.chat.id, "🔌 Ingrese IP para Escaneo Nmap Real:")
    bot.register_next_step_handler(msg, process_nmap_standard)

def process_nmap_standard(message):
    target = message.text
    bot.send_message(message.chat.id, f"⚡ Escaneando {target}...")
    res = exec_nmap_pro(target, "standard")
    bot.send_message(message.chat.id, f"📋 *Resultados:* \n`{res}`", parse_mode="Markdown")

@bot.message_handler(commands=['exploit_deep'])
def deep_recon_cmd(message):
    msg = bot.send_message(message.chat.id, "💀 Ingrese Target para RECON PROFUNDO (Vulnerabilidades):")
    bot.register_next_step_handler(msg, process_nmap_deep)

def process_nmap_deep(message):
    target = message.text
    bot.send_message(message.chat.id, "🌪️ Iniciando escaneo de servicios y versiones (NSE)...")
    res = exec_nmap_pro(target, "deep")
    pdf_path = generar_pdf_profesional(target, res, "AUDITORIA_PROFUNDA")
    with open(pdf_path, "rb") as f:
        bot.send_document(message.chat.id, f, caption="☢️ Reporte de Vulnerabilidades Críticas")
    os.remove(pdf_path)
    db.registrar_operacion(target, "DEEP_RECON")

@bot.message_handler(commands=['scan_url'])
def cmd_scan_url(message):
    msg = bot.reply_to(message, "🔍 Ingrese el DOMINIO o URL para analizar:")
    bot.register_next_step_handler(msg, process_netlas_url)

def process_netlas_url(message):
    target = message.text
    log_operacion("scan_url", target)
    bot.send_message(message.chat.id, f"📡 Consultando infraestructura para: `{target}`...", parse_mode="Markdown")
    try:
        res = n_api.query(query=f"host:{target}")
        data = json.dumps(res, indent=2)
        bot.send_message(message.chat.id, f"📊 *Hallazgos:* \n`{data[:1000]}`", parse_mode="Markdown")
    except:
        bot.send_message(message.chat.id, "❌ Error: Dominio no encontrado o API caída.")

@bot.message_handler(commands=['scan_mx'])
def cmd_scan_mx(message):
    msg = bot.reply_to(message, "🇲🇽 Ingrese término de búsqueda para México (ej. Gobierno, Telmex):")
    bot.register_next_step_handler(msg, process_netlas_mx)

def process_netlas_mx(message):
    target = message.text
    log_operacion("scan_mx", target)
    bot.send_message(message.chat.id, f"🇲🇽 Rastreando activos en MX para: `{target}`...", parse_mode="Markdown")
    try:
        res = n_api.query(query=f"{target} geo.country:MX")
        bot.send_message(message.chat.id, f"📡 *Resultados México:* \n`{str(res)[:1000]}`", parse_mode="Markdown")
    except:
        bot.send_message(message.chat.id, "❌ Error en búsqueda regional.")

@bot.message_handler(commands=['geo_ip'])
def cmd_geo_ip(message):
    msg = bot.reply_to(message, "📍 Ingrese la dirección IP para geolocalizar:")
    bot.register_next_step_handler(msg, process_geo_ip)

def process_geo_ip(message):
    target = message.text
    log_operacion("geo_ip", target)
    bot.send_message(message.chat.id, f"📍 Localizando IP: `{target}`...", parse_mode="Markdown")
    try:
        res = n_api.query(query=f"ip:{target}")
        bot.send_message(message.chat.id, f"🗺️ *Geolocalización:* \n`{str(res)[:1000]}`", parse_mode="Markdown")
    except:
        bot.send_message(message.chat.id, "❌ Error: IP inválida o sin datos.")

# --- COMANDO LEAK (NO SIMULADO - OSINT REAL) ---

@bot.message_handler(commands=['leak'])
def cmd_leak(message):
    msg = bot.reply_to(message, "👤 Ingrese Correo o Nombre completo (Búsqueda OSINT Real):")
    bot.register_next_step_handler(msg, process_real_leak)

@bot.message_handler(commands=['check_pendientes'])
def pendientes(message):
    conn = sqlite3.connect('zenith_titan.db')
    cursor = conn.cursor()
    cursor.execute("SELECT target, fecha FROM objetivos WHERE estado_pago = 0")
    data = cursor.fetchall()
    if data:
        resp = "🚨 *OBJETIVOS CON PAGO PENDIENTE:* \n"
        for r in data: resp += f"• `{r[0]}` - Registrado el {r[1]}\n"
        bot.send_message(message.chat.id, resp, parse_mode="Markdown")
    else:
        bot.send_message(message.chat.id, "✅ No hay deudas pendientes.")

@bot.message_handler(commands=['combos'])
def cmd_combos(message):
    markup = types.InlineKeyboardMarkup(row_width=1)
    # Botones para generar búsquedas automáticas
    btn1 = types.InlineKeyboardButton("🔍 Buscar Combos Gmail (TXT)", callback_data="dork_1")
    btn2 = types.InlineKeyboardButton("🔍 Buscar Logs en Pastebin", callback_data="dork_2")
    btn3 = types.InlineKeyboardButton("🔍 Buscar Dumps SQL", callback_data="dork_3")
    btn4 = types.InlineKeyboardButton("🔍 Buscar Archivos .ENV", callback_data="dork_4")
    markup.add(btn1, btn2, btn3, btn4)

    texto_combos = (
        "🎯 *CENTRO DE INTELIGENCIA DE COMBOS & LOGS*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Seleccione una categoría para generar un enlace de búsqueda OSINT directo en Google:"
    )
    bot.send_message(message.chat.id, texto_combos, parse_mode="Markdown", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith('dork_'))
def callback_dorks(call):
    base_url = "https://www.google.com/search?q="
    dorks = {
        "dork_1": "filetype:txt \"@gmail.com:\" password",
        "dork_2": "site:pastebin.com \"@gmail.com\" pass",
        "dork_3": "filetype:sql \"INSERT INTO\" \"users\" \"password\"",
        "dork_4": "filetype:env \"DB_PASSWORD\""
    }
    query = quote(dorks[call.data])
    link = base_url + query
    
    bot.answer_callback_query(call.id)
    bot.send_message(call.message.chat.id, f"🚀 *Enlace Generado:*\n\n[CLIC AQUÍ PARA BUSCAR REAL]({link})", parse_mode="Markdown")
    
@bot.message_handler(commands=['exploit'])
def cmd_exploit(message):
    msg = bot.reply_to(message, "🛡️ *MODO CVE:* Ingrese la tecnología o software (ej: `Apache 2.4.49` o `WordPress`):", parse_mode="Markdown")
    bot.register_next_step_handler(msg, procesar_busqueda_exploit)

def procesar_busqueda_exploit(message):
    tech = message.text
    bot.send_message(message.chat.id, f"🔎 Consultando base de datos NIST para: `{tech}`...", parse_mode="Markdown")
    
    hallazgos = buscar_cves_reales(tech)
    
    if not hallazgos:
        bot.send_message(message.chat.id, "❌ No se encontraron vulnerabilidades registradas para esa tecnología.")
        return

    # Construir contenido para el PDF y el mensaje
    reporte_texto = f"INFORME DE VULNERABILIDADES PARA: {tech}\n"
    reporte_texto += "="*50 + "\n\n"
    
    for v in hallazgos[:8]:  # Limitamos a los 8 exploits más recientes
        cve_id = v['cve']['id']
        descripcion = v['cve']['descriptions'][0]['value']
        # Intentamos obtener la métrica de severidad (CVSS)
        try:
            score = v['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
            nivel = v['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
        except:
            score = "N/A"
            nivel = "DESCONOCIDO"
            
        reporte_texto += f"ID: {cve_id} | SCORE: {score} ({nivel})\n"
        reporte_texto += f"DESCRIPCIÓN: {descripcion[:200]}...\n"
        reporte_texto += f"MÁS INFO: https://nvd.nist.gov/vuln/detail/{cve_id}\n"
        reporte_texto += "-"*50 + "\n"

    # Generar PDF Profesional
    pdf = ZenithPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "REPORTE TÉCNICO DE EXPLOITS Y CVE", ln=True)
    pdf.set_font("Arial", size=9)
    pdf.multi_cell(0, 6, txt=reporte_texto)
    
    nombre_archivo = f"Exploits_{tech.replace(' ', '_')}.pdf"
    pdf.output(nombre_archivo)
    
    # Enviar al usuario
    with open(nombre_archivo, "rb") as f:
        bot.send_document(message.chat.id, f, caption=f"☢️ Hallazgos de seguridad para `{tech}`.")
    
    os.remove(nombre_archivo)
    log_operacion("exploit_search", tech) # Registro en tu base de datos zenith_master.db   

@bot.message_handler(commands=['status'])
def status_check(message):
    uptime = "Activo"
    db_status = "Conectado"
    nmap_status = "Instalado" if os.system("nmap --version > /dev/null 2>&1") == 0 else "Faltante"
    bot.send_message(message.chat.id, f"⚙️ *ESTADO DEL SISTEMA* \n\nUptime: {uptime}\nBase de Datos: {db_status}\nNmap Engine: {nmap_status}\nAPI Netlas: OK", parse_mode="Markdown")

# === INICIO DEL SISTEMA ===
if __name__ == "__main__":
    os.system("clear")
    print(f"""
    #######################################
    #   DARCKONE v46.0 FULL    #
    #   Sovereign Intelligence Suite      #
    #######################################
    """)
    bot.infinity_polling()
