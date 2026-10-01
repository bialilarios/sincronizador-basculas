"""
Servidor de licencias — Sincronizador Orosys Básculas
FastAPI + SQLite
"""
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import sqlite3, os, secrets, math, hmac, time
from zoneinfo import ZoneInfo

# Hora de México para todo el servidor (Railway corre en UTC)
_TZ = ZoneInfo("America/Monterrey")
def _ahora():
    return datetime.now(_TZ).replace(tzinfo=None)

def _dias_restantes(vence):
    seg = (vence - _ahora()).total_seconds()
    return max(0, math.ceil(seg / 86400))

app = FastAPI(title="Licencias Sincronizador")

# Railway: usar /data/ para persistencia. Si no existe, usar directorio actual.
_data_dir = "/data" if os.path.isdir("/data") else "."
DB_PATH = os.environ.get("DB_PATH", os.path.join(_data_dir, "licencias.db"))
API_KEY = os.environ.get("API_KEY", "cambia-esta-clave-secreta")

# Panel móvil: usuario y contraseña (variables de Railway). Sin ellas, el panel queda deshabilitado.
ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")
SESION_DIAS = 30
_intentos_login = {}  # ip -> [fallos, primer_fallo_ts]

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS historial_activaciones (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                clave        TEXT NOT NULL,
                machine_id   TEXT,
                hostname     TEXT,
                accion       TEXT,  -- activar, desvincular, renovar
                fecha        TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS equipos_conocidos (
                machine_id   TEXT PRIMARY KEY,
                hostname     TEXT,
                primera_vez  TEXT,
                ultima_vez   TEXT
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS sesiones (
                token   TEXT PRIMARY KEY,
                creada  TEXT NOT NULL,
                expira  TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS licencias (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                clave             TEXT UNIQUE NOT NULL,
                cliente           TEXT NOT NULL,
                negocio           TEXT,
                plan              TEXT NOT NULL DEFAULT 'mensual',
                dias              INTEGER NOT NULL DEFAULT 30,
                machine_id        TEXT,
                activada          INTEGER DEFAULT 0,
                activa            INTEGER DEFAULT 1,
                fecha_creacion    TEXT NOT NULL,
                fecha_activacion  TEXT,
                fecha_vencimiento TEXT,
                ultima_edicion    TEXT,
                notas             TEXT
            )
        """)
        # Migraciones: agregar columnas si no existen en BD ya creadas
        columnas = [r[1] for r in db.execute("PRAGMA table_info(licencias)").fetchall()]
        for col, sql in [
            ("ultima_edicion", "ALTER TABLE licencias ADD COLUMN ultima_edicion TEXT"),
            ("negocio",        "ALTER TABLE licencias ADD COLUMN negocio TEXT"),
            ("machine_anterior", "ALTER TABLE licencias ADD COLUMN machine_anterior TEXT"),
        ]:
            if col not in columnas:
                db.execute(sql)
        # Migración para tabla historial_activaciones
        try:
            hist_cols = [r[1] for r in db.execute("PRAGMA table_info(historial_activaciones)").fetchall()]
            if "hostname" not in hist_cols:
                db.execute("ALTER TABLE historial_activaciones ADD COLUMN hostname TEXT")
        except Exception:
            pass
        _limpiar_fechas_sin_activar(db)
        db.commit()


def _limpiar_fechas_sin_activar(db):
    """Regla: una licencia que nunca se ha activado no tiene vencimiento; sus días
    empiezan a contar al activarse. Quita cualquier fecha que haya quedado."""
    filas = db.execute("""SELECT clave, fecha_vencimiento FROM licencias
                          WHERE fecha_activacion IS NULL AND fecha_vencimiento IS NOT NULL""").fetchall()
    for f in filas:
        db.execute("UPDATE licencias SET fecha_vencimiento=NULL WHERE clave=?", (f["clave"],))
        if f["fecha_vencimiento"]:
            db.execute("INSERT INTO historial_activaciones (clave,machine_id,hostname,accion,fecha) VALUES (?,?,?,?,?)",
                       (f["clave"], "", "", "ajuste: se quito la fecha " + str(f["fecha_vencimiento"])[:10] +
                        " (sin activar: los dias cuentan desde la activacion) [servidor]", _ahora().isoformat()))
    return len(filas)

init_db()

class CrearLicencia(BaseModel):
    cliente: str
    negocio: Optional[str] = ""
    plan:    str = "mensual"
    dias:    int = 30
    notas:   Optional[str] = ""
    clave:   Optional[str] = None  # clave manual opcional

class ActivarLicencia(BaseModel):
    clave:      str
    machine_id: str
    hostname:   Optional[str] = ""

class VerificarLicencia(BaseModel):
    clave:      str
    machine_id: str

class ModificarLicencia(BaseModel):
    cliente:           Optional[str] = None
    negocio:           Optional[str] = None
    plan:              Optional[str] = None
    dias:              Optional[int] = None
    activa:            Optional[int] = None
    notas:             Optional[str] = None
    extender_dias:     Optional[int] = None
    fecha_vencimiento: Optional[str] = None  # ISO format: YYYY-MM-DDTHH:MM:SS

def check_key(x_api_key: str):
    if x_api_key and hmac.compare_digest(x_api_key, API_KEY):
        return
    if x_api_key and x_api_key.startswith("ses_"):
        with get_db() as db:
            ses = db.execute("SELECT expira FROM sesiones WHERE token=?", (x_api_key,)).fetchone()
        if ses and datetime.fromisoformat(ses["expira"]) > _ahora():
            return
    raise HTTPException(401, "API Key invalida.")

def _origen(x_api_key: str) -> str:
    return "celular" if (x_api_key or "").startswith("ses_") else "PC"

def dias_para_plan(plan: str) -> int:
    return {"mensual":30,"trimestral":90,"semestral":180,"anual":365}.get(plan, 30)

@app.post("/activar")
def activar(data: ActivarLicencia):
    with get_db() as db:
        lic = db.execute("SELECT * FROM licencias WHERE clave=?", (data.clave,)).fetchone()
        if not lic:
            raise HTTPException(404, "Licencia no encontrada.")
        if not lic["activa"]:
            raise HTTPException(403, "Licencia pausada.")
        ahora = _ahora()
        vencida = bool(lic["fecha_vencimiento"]) and ahora > datetime.fromisoformat(lic["fecha_vencimiento"])
        otro_equipo = bool(lic["activada"] and lic["machine_id"] and lic["machine_id"] != data.machine_id)
        if otro_equipo:
            # Vigente o vencida: solo se mueve si se desvincula desde el Gestor, el panel o el propio equipo
            raise HTTPException(403, "Licencia ya activada en otro equipo. Contacta a soporte.")
        # Mismo equipo: permitir reactivar sin problema
        if lic["fecha_vencimiento"] and lic["fecha_activacion"]:
            # Ya se había activado antes: respetar su vencimiento (reactivar no regala días)
            vence = datetime.fromisoformat(lic["fecha_vencimiento"])
            db.execute("""UPDATE licencias SET activada=1, machine_id=?,
                          machine_anterior=CASE WHEN machine_anterior=? THEN NULL ELSE machine_anterior END,
                          fecha_activacion=? WHERE clave=?""",
                       (data.machine_id, data.machine_id, ahora.isoformat(), data.clave))
        else:
            # Primera activación: calcular fecha desde hoy
            vence = ahora + timedelta(days=lic["dias"])
            db.execute("""UPDATE licencias SET activada=1, machine_id=?, machine_anterior=NULL,
                          fecha_activacion=?, fecha_vencimiento=? WHERE clave=?""",
                       (data.machine_id, ahora.isoformat(), vence.isoformat(), data.clave))
        # Guardar en historial y equipos conocidos
        db.execute("""INSERT INTO historial_activaciones (clave,machine_id,hostname,accion,fecha)
                      VALUES (?,?,?,?,?)""",
                   (data.clave, data.machine_id, data.hostname or "",
                    "activar_vencida" if vencida else "activar", ahora.isoformat()))
        db.execute("""INSERT OR REPLACE INTO equipos_conocidos (machine_id,hostname,primera_vez,ultima_vez)
                      VALUES (?,?,COALESCE((SELECT primera_vez FROM equipos_conocidos WHERE machine_id=?),?),?)""",
                   (data.machine_id, data.hostname or "", data.machine_id, ahora.isoformat(), ahora.isoformat()))
        db.commit()
    return {"ok": True, "cliente": lic["cliente"], "vence": vence.strftime("%d/%m/%Y"),
            "vencida": ahora > vence}

@app.post("/verificar")
def verificar(data: VerificarLicencia):
    with get_db() as db:
        lic = db.execute("SELECT * FROM licencias WHERE clave=?", (data.clave,)).fetchone()
    if not lic:
        raise HTTPException(403, "Licencia no encontrada.")
    if lic["machine_id"] != data.machine_id:
        if lic["machine_id"] and lic["machine_anterior"] == data.machine_id:
            raise HTTPException(403, "Licencia activada en otro equipo.")
        raise HTTPException(403, "Licencia no vinculada a este equipo.")
    if not lic["activa"]:
        raise HTTPException(403, "Licencia pausada.")
    if lic["fecha_vencimiento"]:
        vence = datetime.fromisoformat(lic["fecha_vencimiento"])
        if _ahora() > vence:
            raise HTTPException(403, f"Licencia vencida el {vence.strftime('%d/%m/%Y')}.")
        dias_r = _dias_restantes(vence)
        return {"ok": True, "cliente": lic["cliente"],
                "vence": vence.strftime("%d/%m/%Y"), "dias_restantes": dias_r,
                "machine_id": lic["machine_id"] or "", "negocio": lic["negocio"] or ""}
    return {"ok": True, "cliente": lic["cliente"], "vence": "Permanente",
            "machine_id": lic["machine_id"] or "", "negocio": lic["negocio"] or ""}

@app.post("/admin/crear")
def crear(data: CrearLicencia, x_api_key: str = Header(...)):
    check_key(x_api_key)
    if data.clave:
        clave = data.clave.upper().strip()
        if not clave:
            raise HTTPException(400, "La clave no puede estar vacía.")
    else:
        clave = secrets.token_hex(8).upper()
    dias  = data.dias if data.plan == "personalizado" else dias_para_plan(data.plan)
    with get_db() as db:
        db.execute("""INSERT INTO licencias
                      (clave,cliente,negocio,plan,dias,fecha_creacion,notas)
                      VALUES (?,?,?,?,?,?,?)""",
                   (clave, data.cliente, data.negocio, data.plan, dias,
                    _ahora().isoformat(), data.notas))
        db.execute("INSERT INTO historial_activaciones (clave,machine_id,hostname,accion,fecha) VALUES (?,?,?,?,?)",
                   (clave, "", "", f"crear: {dias} dias [{_origen(x_api_key)}]", _ahora().isoformat()))
        db.commit()
    return {"clave": clave, "cliente": data.cliente, "plan": data.plan, "dias": dias}

@app.get("/admin/listar")
def listar(x_api_key: str = Header(...)):
    check_key(x_api_key)
    with get_db() as db:
        rows = db.execute("SELECT * FROM licencias ORDER BY id DESC").fetchall()
    resultado = []
    for r in rows:
        d = dict(r)
        if d["fecha_vencimiento"]:
            vence = datetime.fromisoformat(d["fecha_vencimiento"])
            d["dias_restantes"] = _dias_restantes(vence)
            d["vencida"] = _ahora() > vence
        else:
            d["dias_restantes"] = None
            d["vencida"] = False
        resultado.append(d)
    return resultado

@app.patch("/admin/modificar/{clave}")
def modificar(clave: str, data: ModificarLicencia, x_api_key: str = Header(...)):
    check_key(x_api_key)
    with get_db() as db:
        lic = db.execute("SELECT * FROM licencias WHERE clave=?", (clave,)).fetchone()
        if not lic:
            raise HTTPException(404, "Licencia no encontrada.")
        campos = {}
        if data.cliente  is not None: campos["cliente"] = data.cliente
        if data.negocio  is not None: campos["negocio"] = data.negocio
        if data.plan     is not None: campos["plan"]    = data.plan
        if data.dias     is not None: campos["dias"]    = data.dias
        if data.activa             is not None: campos["activa"]            = data.activa
        if data.notas              is not None: campos["notas"]             = data.notas
        if data.fecha_vencimiento  is not None:
            if data.fecha_vencimiento == "":
                # Quitar la fecha: solo en licencias que nunca se activaron (sus días vuelven a
                # contar desde la activación). En una ya activada la dejaría como "Permanente".
                if lic["fecha_activacion"]:
                    raise HTTPException(400, "Solo se puede quitar la fecha a licencias que nunca se han activado.")
                campos["fecha_vencimiento"] = None
            else:
                if not lic["fecha_activacion"]:
                    raise HTTPException(400, "Las licencias sin activar no tienen fecha: sus dias empiezan "
                                             "a contar al activarse. Cambia su duracion (dias).")
                try:
                    datetime.fromisoformat(data.fecha_vencimiento)
                except ValueError:
                    raise HTTPException(400, "Fecha de vencimiento no valida.")
                campos["fecha_vencimiento"] = data.fecha_vencimiento
        if data.extender_dias and not lic["fecha_activacion"]:
            campos["dias"] = (data.dias if data.dias is not None else (lic["dias"] or 0)) + data.extender_dias
        elif data.extender_dias and lic["fecha_vencimiento"]:
            vence_actual = datetime.fromisoformat(lic["fecha_vencimiento"])
            nueva = max(vence_actual, _ahora()) + timedelta(days=data.extender_dias)
            campos["fecha_vencimiento"] = nueva.isoformat()
        if campos:
            ahora_m = _ahora().isoformat()
            campos["ultima_edicion"] = ahora_m
            sets = ", ".join(f"{k}=?" for k in campos)
            db.execute(f"UPDATE licencias SET {sets} WHERE clave=?",
                       (*campos.values(), clave))
            # Registrar en historial
            campos_str = ", ".join(f"{k}={v}" for k,v in campos.items() if k != "ultima_edicion")
            mid_m = lic["machine_id"] or ""
            db.execute("INSERT INTO historial_activaciones (clave,machine_id,hostname,accion,fecha) VALUES (?,?,?,?,?)",
                       (clave, mid_m, "", f"editar [{_origen(x_api_key)}]: " + campos_str[:80], ahora_m))
            db.commit()
    return {"ok": True}

@app.post("/admin/renovar/{clave}")
def renovar(clave: str, dias: int, x_api_key: str = Header(...)):
    check_key(x_api_key)
    with get_db() as db:
        lic = db.execute("SELECT * FROM licencias WHERE clave=?", (clave,)).fetchone()
        if not lic:
            raise HTTPException(404, "Licencia no encontrada.")
        ahora = _ahora()
        # Nunca activada y sin fecha: no se le pone vencimiento. Los días se suman a su
        # duración y empiezan a contar hasta que se active.
        if not lic["fecha_activacion"]:
            dias_total = (lic["dias"] or 0) + dias
            db.execute("UPDATE licencias SET activa=1, dias=?, fecha_vencimiento=NULL, ultima_edicion=? WHERE clave=?",
                       (dias_total, ahora.isoformat(), clave))
            db.execute("INSERT INTO historial_activaciones (clave,machine_id,hostname,accion,fecha) VALUES (?,?,?,?,?)",
                       (clave, "", "", f"renovar_sin_activar +{dias}d (total {dias_total} dias al activarse) [{_origen(x_api_key)}]",
                        ahora.isoformat()))
            db.commit()
            return {"ok": True, "nueva_vence": "", "sin_activar": True, "dias_total": dias_total,
                    "desvinculado": False}
        # Base: si la licencia ya venció, partir de hoy a medianoche (sin horas sobrantes)
        # Si aún está vigente, sumar desde el vencimiento actual
        if lic["fecha_vencimiento"]:
            v = datetime.fromisoformat(lic["fecha_vencimiento"])
            if v > ahora:
                # Vigente: sumar desde vencimiento, pero sin horas (solo fecha)
                base = v
            else:
                # Vencida: partir de hoy a medianoche
                base = ahora
        else:
            base = ahora
        nueva_vence = base + timedelta(days=dias)
        # Al renovar: reactivar y mantener machine_id para que el equipo no pierda acceso
        # Si la licencia está vencida → desvincular equipo (libre para activarse en otro)
        # Si está vigente → mantener equipo vinculado, solo extender fecha
        # Vencida o vigente: se conserva el equipo; se reactiva sola en el que la tenga
        ya_vencida = bool(lic["fecha_vencimiento"]) and datetime.fromisoformat(lic["fecha_vencimiento"]) < ahora
        db.execute("""UPDATE licencias SET activa=1, fecha_vencimiento=?, dias=?,
                      ultima_edicion=? WHERE clave=?""",
                   (nueva_vence.isoformat(), dias, ahora.isoformat(), clave))
        mid_r = lic["machine_id"] or ""
        # Obtener hostname del equipo
        eq_r = db.execute("SELECT hostname FROM equipos_conocidos WHERE machine_id=?", (mid_r,)).fetchone()
        hostname_r = (eq_r["hostname"] if eq_r else "") or ""
        accion_r = ("renovar_vencida" if ya_vencida else "renovar_vigente") + f" +{dias}d hasta {nueva_vence.strftime('%d/%m/%Y')}"
        db.execute("INSERT INTO historial_activaciones (clave,machine_id,hostname,accion,fecha) VALUES (?,?,?,?,?)",
                   (clave, mid_r, hostname_r, accion_r + f" [{_origen(x_api_key)}]", ahora.isoformat()))
        db.commit()
    return {"ok": True, "nueva_vence": nueva_vence.strftime("%d/%m/%Y"),
            "desvinculado": False}

@app.post("/admin/desvincular/{clave}")
def desvincular(clave: str, x_api_key: str = Header(...)):
    """Desvincula la licencia del equipo actual para que pueda activarse en otro."""
    check_key(x_api_key)
    with get_db() as db:
        lic = db.execute("SELECT * FROM licencias WHERE clave=?", (clave,)).fetchone()
        if not lic:
            raise HTTPException(404, "Licencia no encontrada.")
        ahora_d = _ahora().isoformat()
        mid_d = lic["machine_id"] or "" if lic["machine_id"] else ""
        db.execute("""UPDATE licencias SET machine_id=NULL, machine_anterior=?, activada=0,
                      ultima_edicion=? WHERE clave=?""",
                   (lic["machine_id"], ahora_d, clave))
        db.execute("INSERT INTO historial_activaciones (clave,machine_id,hostname,accion,fecha) VALUES (?,?,?,?,?)",
                   (clave, mid_d, "", f"desvincular_admin [{_origen(x_api_key)}]", ahora_d))
        db.commit()
    return {"ok": True}

@app.patch("/admin/cambiar-clave/{clave}")
def cambiar_clave(clave: str, body: dict, x_api_key: str = Header(...)):
    check_key(x_api_key)
    nueva_clave = body.get("nueva_clave","").upper()
    if not nueva_clave:
        raise HTTPException(400, "Clave nueva requerida.")
    with get_db() as db:
        lic = db.execute("SELECT * FROM licencias WHERE clave=?", (clave,)).fetchone()
        if not lic:
            raise HTTPException(404, "Licencia no encontrada.")
        db.execute("""UPDATE licencias SET clave=?, machine_id=NULL, machine_anterior=NULL, activada=0,
                      ultima_edicion=? WHERE clave=?""",
                   (nueva_clave, _ahora().isoformat(), clave))
        db.commit()
    return {"ok": True, "nueva_clave": nueva_clave}

@app.delete("/admin/eliminar/{clave}")
def eliminar(clave: str, x_api_key: str = Header(...)):
    check_key(x_api_key)
    with get_db() as db:
        lic = db.execute("SELECT * FROM licencias WHERE clave=?", (clave,)).fetchone()
        if not lic:
            raise HTTPException(404, "Licencia no encontrada.")
        foto = (f"eliminar [{_origen(x_api_key)}]: cliente={lic['cliente']}, negocio={lic['negocio'] or ''}, "
                f"plan={lic['plan']}, dias={lic['dias']}, vencia={lic['fecha_vencimiento'] or 'sin activar'}, "
                f"notas={lic['notas'] or ''}")
        db.execute("INSERT INTO historial_activaciones (clave,machine_id,hostname,accion,fecha) VALUES (?,?,?,?,?)",
                   (clave, lic["machine_id"] or "", "", foto, _ahora().isoformat()))
        db.execute("DELETE FROM licencias WHERE clave=?", (clave,))
        db.commit()
    return {"ok": True}

@app.get("/admin/eliminadas")
def eliminadas(x_api_key: str = Header(...)):
    check_key(x_api_key)
    with get_db() as db:
        rows = db.execute("""SELECT clave, accion, fecha FROM historial_activaciones
                             WHERE accion LIKE 'eliminar%' ORDER BY fecha DESC LIMIT 200""").fetchall()
    return [dict(r) for r in rows]

@app.get("/admin/exportar")
def exportar(x_api_key: str = Header(...)):
    check_key(x_api_key)
    with get_db() as db:
        rows = db.execute("SELECT * FROM licencias ORDER BY id").fetchall()
    return {"licencias": [dict(r) for r in rows], "total": len(rows),
            "exportado": _ahora().isoformat()}

@app.post("/admin/importar")
def importar(body: dict, x_api_key: str = Header(...)):
    check_key(x_api_key)
    licencias = body.get("licencias", [])
    if not licencias:
        raise HTTPException(400, "No hay licencias en el payload.")
    with get_db() as db:
        for l in licencias:
            db.execute("""
                INSERT OR REPLACE INTO licencias
                (id,clave,cliente,negocio,plan,dias,machine_id,activada,activa,
                 fecha_creacion,fecha_activacion,fecha_vencimiento,ultima_edicion,notas)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                l.get("id"), l.get("clave"), l.get("cliente"), l.get("negocio"),
                l.get("plan","mensual"), l.get("dias",30), l.get("machine_id"),
                l.get("activada",0), l.get("activa",1),
                l.get("fecha_creacion"), l.get("fecha_activacion"),
                l.get("fecha_vencimiento"), l.get("ultima_edicion"), l.get("notas")
            ))
        _limpiar_fechas_sin_activar(db)
        db.commit()
    return {"ok": True, "importadas": len(licencias)}

@app.post("/desvincular-cliente")
def desvincular_cliente(data: ActivarLicencia):
    """Endpoint publico — el cliente desvincula su propio equipo."""
    with get_db() as db:
        lic = db.execute(
            "SELECT * FROM licencias WHERE clave=? AND machine_id=?",
            (data.clave, data.machine_id)
        ).fetchone()
        if not lic:
            raise HTTPException(404, "Licencia no encontrada en este equipo.")
        ahora_c = _ahora().isoformat()
        db.execute("""UPDATE licencias SET machine_id=NULL, machine_anterior=NULL, activada=0,
                      ultima_edicion=? WHERE clave=?""",
                   (ahora_c, data.clave))
        db.execute("INSERT INTO historial_activaciones (clave,machine_id,hostname,accion,fecha) VALUES (?,?,?,?,?)",
                   (data.clave, data.machine_id, "", "desvincular_cliente", ahora_c))
        db.commit()
    return {"ok": True}

@app.get("/admin/historial/{clave}")
def historial(clave: str, x_api_key: str = Header(...)):
    check_key(x_api_key)
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM historial_activaciones WHERE clave=? ORDER BY fecha DESC LIMIT 50",
            (clave,)
        ).fetchall()
        equipo = db.execute(
            "SELECT * FROM equipos_conocidos WHERE machine_id=(SELECT machine_id FROM licencias WHERE clave=?)",
            (clave,)
        ).fetchone()
    return {
        "historial": [dict(r) for r in rows],
        "equipo_actual": dict(equipo) if equipo else None
    }

@app.get("/admin/equipos")
def equipos(x_api_key: str = Header(...)):
    check_key(x_api_key)
    with get_db() as db:
        rows = db.execute("SELECT * FROM equipos_conocidos ORDER BY ultima_vez DESC").fetchall()
    return [dict(r) for r in rows]

class LoginData(BaseModel):
    usuario:  str
    password: str

@app.post("/admin/login")
def login(data: LoginData, request: Request):
    if not ADMIN_USER or not ADMIN_PASS:
        raise HTTPException(503, "Panel deshabilitado: faltan ADMIN_USER y ADMIN_PASS en el servidor.")
    ip = request.client.host if request.client else "?"
    ahora_ts = time.time()
    fallos, desde = _intentos_login.get(ip, [0, ahora_ts])
    if ahora_ts - desde > 900:
        fallos, desde = 0, ahora_ts
    if fallos >= 5:
        raise HTTPException(429, "Demasiados intentos. Espera 15 minutos.")
    ok = hmac.compare_digest(data.usuario, ADMIN_USER) and hmac.compare_digest(data.password, ADMIN_PASS)
    if not ok:
        _intentos_login[ip] = [fallos + 1, desde]
        raise HTTPException(401, "Usuario o contrasena incorrectos.")
    _intentos_login.pop(ip, None)
    token = "ses_" + secrets.token_urlsafe(32)
    ahora = _ahora()
    with get_db() as db:
        db.execute("DELETE FROM sesiones WHERE expira < ?", (ahora.isoformat(),))
        db.execute("INSERT INTO sesiones (token, creada, expira) VALUES (?,?,?)",
                   (token, ahora.isoformat(), (ahora + timedelta(days=SESION_DIAS)).isoformat()))
        db.commit()
    return {"ok": True, "token": token}

@app.post("/admin/logout")
def logout(x_api_key: str = Header(...)):
    with get_db() as db:
        db.execute("DELETE FROM sesiones WHERE token=?", (x_api_key,))
        db.commit()
    return {"ok": True}

@app.post("/admin/cerrar-sesiones")
def cerrar_sesiones(x_api_key: str = Header(...)):
    """Cierra todas las sesiones del panel (por si se pierde el celular)."""
    check_key(x_api_key)
    with get_db() as db:
        db.execute("DELETE FROM sesiones")
        db.commit()
    return {"ok": True}

@app.get("/panel", response_class=HTMLResponse)
def panel():
    ruta = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.html")
    with open(ruta, encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-store"})

@app.get("/")
def root():
    return {"status": "ok", "servicio": "Licencias Sincronizador Orosys",
            "version": "2026.10.01b", "hora_servidor": _ahora().strftime("%d/%m/%Y %H:%M:%S")}
