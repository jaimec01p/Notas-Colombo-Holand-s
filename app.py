from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import re
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import secrets
import string

app = Flask(__name__)
app.secret_key = "cambia-esto"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///CCH.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    identificacion = db.Column(db.String(20), unique = True, nullable = False)
    nombres = db.Column(db.String(120), nullable=False)
    apellidos = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(20), nullable=False, default="docente")
    activo = db.Column(db.Boolean, default=True)

class LlaveRegistro(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(100), unique=True, nullable=False)

    rol_permitido = db.Column(db.String(30), nullable=False)   # docente, admin, admin_profesor

    usada = db.Column(db.Boolean, default=False, nullable=False)
    usada_por = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=True)

    activa = db.Column(db.Boolean, default=True, nullable=False)

    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    fecha_expiracion = db.Column(db.DateTime, nullable=False)

    creada_por = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=True)

def generar_codigo_llave(prefijo):
    caracteres = string.ascii_uppercase + string.digits
    bloques = ["".join(secrets.choice(caracteres) for _ in range(4)) for _ in range(3)]
    return f"{prefijo}-" + "-".join(bloques)

def prefijo_por_rol(rol):
    if rol == "docente":
        return "DOC"
    if rol == "admin":
        return "ADM"
    if rol == "admin_profesor":
        return "COORD"
    return "KEY"

class Salon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    grado = db.Column(db.String(20), nullable=False)
    director = db.Column(db.String(120), nullable=False)

    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=True)

class Materia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(120), nullable=False)    # ej: Matemáticas

    salon_id = db.Column(db.Integer, db.ForeignKey("salon.id"), nullable=False)
    salon = db.relationship("Salon", backref=db.backref("materias", lazy=True, cascade="all, delete-orphan"))

class Estudiante(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    nombres = db.Column(db.String(120), nullable=False)
    apellidos = db.Column(db.String(120), nullable=False)

    salon_id = db.Column(db.Integer, db.ForeignKey("salon.id"), nullable=False)
    salon = db.relationship("Salon", backref=db.backref("estudiantes", lazy=True, cascade="all, delete-orphan"))

class Actividad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(120), nullable=False)

    materia_id = db.Column(db.Integer, db.ForeignKey("materia.id"), nullable=False)
    materia = db.relationship("Materia", backref=db.backref("actividades", lazy=True, cascade="all, delete-orphan"))


class Nota(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    valor = db.Column(db.Float, nullable=True)

    estudiante_id = db.Column(db.Integer, db.ForeignKey("estudiante.id"), nullable=False)
    actividad_id = db.Column(db.Integer, db.ForeignKey("actividad.id"), nullable=False)

    __table_args__ = (
        db.UniqueConstraint("estudiante_id", "actividad_id", name="uq_nota_est_act"),
    )

def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped_view

@app.get("/")
@login_required
def index():
    salones = Salon.query.filter_by(usuario_id=session["usuario_id"]).all()

    def key(s):
        m = re.search(r"\d+", s.grado)
        num = int(m.group()) if m else 0
        return (num, s.grado)
    
    salones = sorted(salones, key=key)
    return render_template("index.html", salones=salones, modal_open=False, form_data={})

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        identificacion = request.form.get("identificacion", "").strip()
        nombres = request.form.get("nombres", "").strip()
        apellidos = request.form.get("apellidos", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        llave = request.form.get("llave", "").strip()

        if not identificacion or not nombres or not apellidos or not email or not password or not confirm_password or not llave:
            flash("Completa todos los campos.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Las contraseñas no coinciden.", "error")
            return render_template("register.html")

        usuario_existente = Usuario.query.filter(
            (Usuario.identificacion == identificacion) |
            (Usuario.email == email)
        ).first()

        if usuario_existente:
            flash("Ya existe un usuario con esa identificación o email.", "error")
            return render_template("register.html")

        llave_registro = LlaveRegistro.query.filter_by(
            codigo=llave,
            usada=False,
            activa=True
        ).first()

        if not llave_registro:
            flash("La llave no es válida, ya fue usada o está desactivada.", "error")
            return render_template("register.html")

        if llave_registro.fecha_expiracion < datetime.utcnow():
            flash("La llave ya expiró.", "error")
            return render_template("register.html")

        rol = llave_registro.rol_permitido

        nuevo_usuario = Usuario(
            identificacion=identificacion,
            nombres=nombres,
            apellidos=apellidos,
            email=email,
            rol=rol,
            password_hash=generate_password_hash(password)
        )

        db.session.add(nuevo_usuario)
        db.session.commit()

        llave_registro.usada = True
        llave_registro.usada_por = nuevo_usuario.id
        db.session.commit()

        flash("Cuenta creada correctamente. Ahora inicia sesión.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identificacion = request.form.get("identificacion", "").strip()
        password = request.form.get("password", "")

        usuario = Usuario.query.filter_by(
            identificacion=identificacion,
            activo=True
        ).first()

        if not usuario or not check_password_hash(usuario.password_hash, password):
            flash("Identificación o contraseña incorrectos.", "error")
            return render_template("login.html")

        session["usuario_id"] = usuario.id
        session["usuario_nombre"] = usuario.nombres
        session["usuario_rol"] = usuario.rol

        if usuario.rol == "admin":
            return redirect(url_for("panel_admin"))

        return redirect(url_for("index"))

    return render_template("login.html")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/admin")
@login_required
def panel_admin():
    if session.get("usuario_rol") not in ["admin", "admin_profesor"]:
        return redirect(url_for("index"))

    usuarios = Usuario.query.order_by(Usuario.apellidos.asc(), Usuario.nombres.asc()).all()
    return render_template("admin.html", usuarios=usuarios)

@app.route("/admin/llaves", methods=["GET", "POST"])
@login_required
def admin_llaves():
    if session.get("usuario_rol") not in ["admin", "admin_profesor"]:
        return redirect(url_for("index"))

    if request.method == "POST":
        rol = request.form.get("rol", "").strip()
        fecha_exp = request.form.get("fecha_expiracion", "").strip()

        if rol not in ["docente", "admin", "admin_profesor"]:
            flash("Selecciona un rol válido.", "error")
            return redirect(url_for("admin_llaves"))

        if not fecha_exp:
            flash("Debes seleccionar una fecha y hora de expiración.", "error")
            return redirect(url_for("admin_llaves"))

        try:
            fecha_expiracion = datetime.strptime(fecha_exp, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Formato de fecha inválido.", "error")
            return redirect(url_for("admin_llaves"))

        if fecha_expiracion <= datetime.utcnow():
            flash("La fecha de expiración debe ser futura.", "error")
            return redirect(url_for("admin_llaves"))

        codigo = generar_codigo_llave(prefijo_por_rol(rol))

        while LlaveRegistro.query.filter_by(codigo=codigo).first():
            codigo = generar_codigo_llave(prefijo_por_rol(rol))

        nueva_llave = LlaveRegistro(
            codigo=codigo,
            rol_permitido=rol,
            fecha_expiracion=fecha_expiracion,
            creada_por=session["usuario_id"]
        )

        db.session.add(nueva_llave)
        db.session.commit()

        flash("Llave creada correctamente.", "success")
        return redirect(url_for("admin_llaves"))

    llaves = LlaveRegistro.query.order_by(LlaveRegistro.fecha_creacion.desc()).all()
    return render_template("admin_llaves.html", llaves=llaves)

@app.get("/admin/docentes")
@login_required
def admin_docentes():
    if session.get("usuario_rol") not in ["admin", "admin_profesor"]:
        return redirect(url_for("index"))

    docentes = Usuario.query.order_by(Usuario.apellidos.asc(), Usuario.nombres.asc()).all()
    return render_template("admin_docentes.html", docentes=docentes)

@app.post("/materia/<int:materia_id>/actividades/crear")
@login_required
def crear_actividad(materia_id):
    materia = Materia.query.get_or_404(materia_id)
    nombre = request.form.get("nombre", "").strip()

    if not nombre:
        flash("Escribe el nombre de la actividad.", "error")
        return redirect(url_for("ver_materia", materia_id=materia.id))

    nueva = Actividad(nombre=nombre, materia_id=materia.id)
    db.session.add(nueva)
    db.session.commit()

    flash("Actividad agregada.", "success")
    return redirect(url_for("ver_materia", materia_id=materia.id))

@app.post("/actividad/<int:actividad_id>/editar")
@login_required
def editar_actividad(actividad_id):
    actividad = Actividad.query.get_or_404(actividad_id)

    materia = (
        Materia.query
        .join(Salon)
        .filter(Materia.id == actividad.materia_id, Salon.usuario_id == session["usuario_id"])
        .first_or_404()
    )

    nombre = request.form.get("nombre", "").strip()

    if not nombre:
        flash("El nombre de la actividad no puede estar vacío.", "error")
        return redirect(url_for("ver_materia", materia_id=materia.id))

    actividad.nombre = nombre
    db.session.commit()

    flash("Actividad actualizada correctamente.", "success")
    return redirect(url_for("ver_materia", materia_id=materia.id))


@app.post("/actividad/<int:actividad_id>/eliminar")
@login_required
def eliminar_actividad(actividad_id):
    actividad = Actividad.query.get_or_404(actividad_id)

    materia = (
        Materia.query
        .join(Salon)
        .filter(Materia.id == actividad.materia_id, Salon.usuario_id == session["usuario_id"])
        .first_or_404()
    )

    db.session.delete(actividad)
    db.session.commit()

    flash("Actividad eliminada correctamente.", "success")
    return redirect(url_for("ver_materia", materia_id=materia.id))

@app.post("/estudiante/<int:estudiante_id>/editar")
@login_required
def editar_estudiante(estudiante_id):
    estudiante = Estudiante.query.get_or_404(estudiante_id)

    # Validar que el estudiante pertenezca a un salón del usuario logueado
    salon = Salon.query.filter_by(
        id=estudiante.salon_id,
        usuario_id=session["usuario_id"]
    ).first_or_404()

    nombres = request.form.get("nombres", "").strip()
    apellidos = request.form.get("apellidos", "").strip()

    if not nombres or not apellidos:
        flash("Completa nombres y apellidos del estudiante.", "error")
        return redirect(url_for("ver_salon", salon_id=salon.id))

    estudiante.nombres = nombres
    estudiante.apellidos = apellidos
    db.session.commit()

    flash("Estudiante actualizado correctamente.", "success")
    return redirect(url_for("ver_salon", salon_id=salon.id))

@app.post("/salon/<int:salon_id>/estudiantes/crear")
@login_required
def crear_estudiante_salon(salon_id):
    salon = Salon.query.filter_by(id=salon_id, usuario_id=session["usuario_id"]).first_or_404()

    nombres = request.form.get("nombres", "").strip()
    apellidos = request.form.get("apellidos", "").strip()

    if not nombres or not apellidos:
        flash("Completa nombres y apellidos.", "error")
        return redirect(url_for("ver_salon", salon_id=salon.id))

    nuevo = Estudiante(nombres=nombres, apellidos=apellidos, salon_id=salon.id)
    db.session.add(nuevo)
    db.session.commit()

    flash("Estudiante agregado.", "success")
    return redirect(url_for("ver_salon", salon_id=salon.id))


@app.post("/salon/<int:salon_id>/materias/crear")
@login_required
def crear_materia(salon_id):
    salon = Salon.query.filter_by(id=salon_id, usuario_id=session["usuario_id"]).first_or_404()
    nombre = request.form.get("nombre", "").strip()

    form_data = {"nombre": nombre}

    if not nombre:
        flash("Escribe el nombre de la materia.", "error")
        materias = Materia.query.filter_by(salon_id=salon_id).order_by(Materia.nombre.asc()).all()
        return render_template("salon.html", salon=salon, materias=materias, modal_open=True, form_data=form_data)

    nueva = Materia(nombre=nombre, salon_id=salon.id)
    db.session.add(nueva)
    db.session.commit()

    flash("Materia agregada.", "success")
    return redirect(url_for("ver_salon", salon_id=salon.id))

@app.post("/notas/guardar")
@login_required
def guardar_nota():
    estudiante_id = request.form.get("estudiante_id", type=int)
    actividad_id = request.form.get("actividad_id", type=int)
    valor = request.form.get("valor", "")

    if not estudiante_id or not actividad_id:
        return jsonify({"ok": False, "error": "Datos incompletos"}), 400

    # borrar nota si queda vacío
    if str(valor).strip() == "":
        nota = Nota.query.filter_by(estudiante_id=estudiante_id, actividad_id=actividad_id).first()
        if nota:
            db.session.delete(nota)
            db.session.commit()
        return jsonify({"ok": True, "saved": None})

    try:
        valor_num = float(valor)
    except ValueError:
        return jsonify({"ok": False, "error": "Valor inválido"}), 400

    nota = Nota.query.filter_by(estudiante_id=estudiante_id, actividad_id=actividad_id).first()
    if nota is None:
        nota = Nota(estudiante_id=estudiante_id, actividad_id=actividad_id, valor=valor_num)
        db.session.add(nota)
    else:
        nota.valor = valor_num

    db.session.commit()
    return jsonify({"ok": True, "saved": valor_num})

@app.post("/salones/crear")
@login_required
def crear_salon():
    grado = request.form.get("grado","").strip()
    director = request.form.get("director","").strip()
    form_data = {"grado": grado, "director": director}

    if not grado or not director:
        flash("Completa grado y director de grupo.", "error")
        salones = Salon.query.filter_by(usuario_id=session["usuario_id"]).all()
        return render_template("index.html", salones=salones, modal_open=True, form_data=form_data)

    nuevo = Salon(
        grado=grado,
        director=director,
        usuario_id=session["usuario_id"]
    )
    db.session.add(nuevo)
    db.session.commit()

    flash("Salón creado correctamente.", "success")
    return redirect(url_for("index"))

@app.get("/salon/<int:salon_id>")
@login_required
def ver_salon(salon_id):
    salon = Salon.query.filter_by(id=salon_id, usuario_id=session["usuario_id"]).first_or_404()

    materias = Materia.query.filter_by(salon_id=salon_id).order_by(Materia.nombre.asc()).all()
    estudiantes = (
        Estudiante.query.filter_by(salon_id=salon_id)
        .order_by(Estudiante.apellidos.asc(), Estudiante.nombres.asc())
        .all()
    )

    return render_template(
        "salon.html",
        salon=salon,
        materias=materias,
        estudiantes=estudiantes,
        modal_open=False,
        form_data={}
    )

@app.get("/materia/<int:materia_id>")
@login_required
def ver_materia(materia_id):
    materia = (
        Materia.query
        .join(Salon)
        .filter(Materia.id == materia_id, Salon.usuario_id == session["usuario_id"])
        .first_or_404()
    )

    estudiantes = Estudiante.query.filter_by(salon_id=materia.salon_id)\
        .order_by(Estudiante.apellidos.asc(), Estudiante.nombres.asc()).all()

    actividades = Actividad.query.filter_by(materia_id=materia.id)\
        .order_by(Actividad.id.asc()).all()

    est_ids = [e.id for e in estudiantes]
    act_ids = [a.id for a in actividades]
    notas_map = {}

    if est_ids and act_ids:
        notas = Nota.query.filter(
            Nota.estudiante_id.in_(est_ids),
            Nota.actividad_id.in_(act_ids)
        ).all()
        notas_map = {(n.estudiante_id, n.actividad_id): n.valor for n in notas}

    return render_template(
        "materias.html",
        materia=materia,
        estudiantes=estudiantes,
        actividades=actividades,
        notas_map=notas_map
    )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)