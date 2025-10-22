# logging_utils.py
import logging
from logging.handlers import RotatingFileHandler
import time
import re
from flask import request

# Configuración del logger
def get_logger(name="app", log_file="app.log", max_bytes=5*1024*1024, backup_count=3, level=logging.INFO):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(level)
        handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

# Regex para detectar tokens típicos de inyección
suspicious_re = re.compile(r"(?:'|\"|;|,|--|/\*|\*/|\&\&|\||\\|\-|/|\*)")

# IDS in-memory state (simple)
IDS_STATE = {
    "attempts": {},
    "blocked": {}
}

# Parametros configurables
N_THRESHOLD = 5           # Número de intentos sospechosos para bloquear
WINDOW_SECONDS = 60      # Ventana de tiempo para contar intentos
BLOCK_SECONDS = 300      # Bloqueo temporal en segundos

def client_ip_from_request(req):
    xff = req.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return req.remote_addr or "unknown"

def log_request(logger, req, result="OK", extra=None):
    ip = client_ip_from_request(req)
    endpoint = req.path
    params = dict(req.args)
    ua = req.headers.get("User-Agent", "")
    logger.info(f"REQUEST ip={ip} endpoint={endpoint} params={params} user_agent=\"{ua}\" result={result} extra={extra}")

def alert(logger, title, details):
    # Notificación/alerta simple
    logger.warning(f"ALERT: {title} - {details}")

def check_and_record_suspicious(logger, req):
    ip = client_ip_from_request(req)

    # Verificar si ya está bloqueada
    now = time.time()
    blocked_until = IDS_STATE["blocked"].get(ip)
    if blocked_until and now < blocked_until:
        return True, f"blocked_until:{blocked_until}"

    suspicious_found = False
    reasons = []

    for k, v in req.args.items():
        if v is None:
            continue
        if suspicious_re.search(v):
            suspicious_found = True
            reasons.append(f"param={k} value={v}")

    if suspicious_found:
        # registrar intento sospechoso
        attempts = IDS_STATE["attempts"].setdefault(ip, [])
        attempts.append(now)
        # limpiar entradas fuera de ventana
        window_start = now - WINDOW_SECONDS
        IDS_STATE["attempts"][ip] = [t for t in attempts if t >= window_start]
        count = len(IDS_STATE["attempts"][ip])

        # alerta de detección
        alert(logger, "Posible inyeccion", {"ip": ip, "count_in_window": count, "reasons": reasons})

        # bloquear si excede umbral
        if count >= N_THRESHOLD:
            IDS_STATE["blocked"][ip] = now + BLOCK_SECONDS
            alert(logger, "IP temporalmente bloqueada", {"ip": ip, "blocked_until": IDS_STATE["blocked"][ip]})
            return True, f"blocked_now;count={count}"

        return True, f"suspicious;count={count};reasons={reasons}"

    return False, None

def record_sql_error(logger, ip, query_snippet, error_str):
    logger.error(f"SQL_ERROR ip={ip} query_snippet=\"{query_snippet}\" error=\"{error_str}\"")
