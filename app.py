# app.py
import sqlite3, os, hashlib
from datetime import datetime
from flask import Flask, g, render_template, request, redirect, session, url_for

app = Flask(__name__)
app.secret_key = "replace-me"  # for production, load from env

DB_PATH = "hms.db"

# ---------- Helpers ----------
def hash_pwd(p):  # very basic hashing (do NOT use in production)
    return hashlib.sha256(p.encode()).hexdigest()

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ---------- Initial set-up ----------
def init_db():
    """Run only if database does not exist."""
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT CHECK(role IN ('admin','doctor','patient'))
        );
        CREATE TABLE IF NOT EXISTS doctors(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            specialization TEXT,
            availability TEXT DEFAULT 'Available'
        );
        CREATE TABLE IF NOT EXISTS doctor_credentials(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER,
            username TEXT UNIQUE,
            password TEXT,
            FOREIGN KEY(doctor_id) REFERENCES doctors(id)
        );
        CREATE TABLE IF NOT EXISTS appointments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            doctor_id  INTEGER,
            date TEXT,
            status TEXT DEFAULT 'Booked',
            diagnosis TEXT,
            notes TEXT,
            FOREIGN KEY(patient_id) REFERENCES users(id),
            FOREIGN KEY(doctor_id) REFERENCES doctors(id)
        );
        """
    )
    # create default admin if absent
    cur = db.execute("SELECT id FROM users WHERE role='admin'")
    if not cur.fetchone():
        db.execute(
            "INSERT INTO users(username, password, role) VALUES (?,?,?)",
            ("admin", hash_pwd("admin"), "admin"),
        )
    db.commit()

# ---------- Authentication ----------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def login_required(r):
    def w(*a, **kw):
        if not current_user():
            return redirect(url_for("login"))
        return r(*a, **kw)
    w.__name__ = r.__name__
    return w

# ---------- Routes ----------
@app.route("/")
def index():
    u = current_user()
    if not u:
        return redirect("/login")
    if u["role"] == "admin":
        return redirect("/admin")
    if u["role"] == "doctor":
        return redirect("/doctor")
    return redirect("/patient")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form.get("u"), request.form.get("p")
        if not u or not p:
            return render_template("login.html", err="Username and password required")
        row = get_db().execute(
            "SELECT * FROM users WHERE username=? AND password=?", (u, hash_pwd(p))
        ).fetchone()
        if row:
            session["uid"] = row["id"]
            return redirect("/")
        return render_template("login.html", err="Invalid credentials")
    return render_template("login.html", err=None)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form.get("u"), request.form.get("p")
        if not u or not p:
            return render_template("register.html", err="Username and password required")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users(username,password,role) VALUES (?,?,?)",
                (u, hash_pwd(p), "patient"),
            )
            db.commit()
            return redirect("/login")
        except sqlite3.IntegrityError:
            return render_template("register.html", err="Username taken")
    return render_template("register.html", err=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# --- admin dashboard route with search ---
@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    u = current_user()
    if u["role"] != "admin":
        return "Forbidden", 403
    db = get_db()
    # Add doctor
    if request.method == "POST" and "name" in request.form and "spec" in request.form:
        name = request.form.get("name", "").strip()
        spec = request.form.get("spec", "").strip()
        if name and spec:
            db.execute(
                "INSERT INTO doctors(name,specialization,availability) VALUES (?,?,?)",
                (name, spec, "Available"),
            )
            db.commit()

    # --- Search logic ---
    doc_search = request.args.get("doc_search", "").strip()
    pat_search = request.args.get("pat_search", "").strip()

    # Doctors search
    if doc_search:
        docs = db.execute(
            "SELECT * FROM doctors WHERE name LIKE ? OR specialization LIKE ?",
            (f"%{doc_search}%", f"%{doc_search}%"),
        ).fetchall()
    else:
        docs = db.execute("SELECT * FROM doctors").fetchall()

    # Patients search
    if pat_search:
        pats = db.execute(
            "SELECT * FROM users WHERE role='patient' AND username LIKE ?",
            (f"%{pat_search}%",),
        ).fetchall()
    else:
        pats = db.execute("SELECT * FROM users WHERE role='patient'").fetchall()

    dcount = db.execute("SELECT count(*) FROM doctors").fetchone()[0]
    pcount = db.execute("SELECT count(*) FROM users WHERE role='patient'").fetchone()[0]
    acount = db.execute("SELECT count(*) FROM appointments").fetchone()[0]

    # Get all appointments with patient and doctor names
    apps_ = db.execute(
        """SELECT a.id, u.username as patient, d.name as doctor, a.date, a.status
           FROM appointments a
           JOIN users u ON a.patient_id = u.id
           JOIN doctors d ON a.doctor_id = d.id
           ORDER BY a.date DESC"""
    ).fetchall()

    # Fetch doctor credentials
    doc_creds = db.execute(
        """SELECT dc.id, d.name, dc.username, dc.password
           FROM doctor_credentials dc
           JOIN doctors d ON dc.doctor_id = d.id"""
    ).fetchall()

    return render_template(
        "admin_dashboard.html",
        dcount=dcount,
        pcount=pcount,
        acount=acount,
        docs=docs,
        pats=pats,
        apps=apps_,
        doc_search=doc_search,
        pat_search=pat_search,
        doc_creds=doc_creds,
    )

@app.route("/admin/edit_doctor/<int:did>", methods=["GET", "POST"])
@login_required
def edit_doctor(did):
    u = current_user()
    if u["role"] != "admin":
        return "Forbidden", 403
    db = get_db()
    doc = db.execute("SELECT * FROM doctors WHERE id=?", (did,)).fetchone()
    if not doc:
        return "Doctor not found", 404
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        spec = request.form.get("spec", "").strip()
        avail = request.form.get("availability", "Available")
        db.execute(
            "UPDATE doctors SET name=?, specialization=?, availability=? WHERE id=?",
            (name, spec, avail, did),
        )
        db.commit()
        return redirect("/admin")
    return render_template("edit_doctor.html", doc=doc)

@app.route("/admin/delete_doctor/<int:did>")
@login_required
def delete_doctor(did):
    u = current_user()
    if u["role"] != "admin":
        return "Forbidden", 403
    db = get_db()
    # Delete related appointments first
    db.execute("DELETE FROM appointments WHERE doctor_id=?", (did,))
    db.execute("DELETE FROM doctors WHERE id=?", (did,))
    db.commit()
    return redirect("/admin")

@app.route("/admin/update_appointment/<int:aid>", methods=["POST"])
@login_required
def admin_update_appointment(aid):
    u = current_user()
    if u["role"] != "admin":
        return "Forbidden", 403
    status = request.form.get("status")
    db = get_db()
    db.execute("UPDATE appointments SET status=? WHERE id=?", (status, aid))
    db.commit()
    return redirect("/admin")

@app.route("/admin/delete_appointment/<int:aid>")
@login_required
def admin_delete_appointment(aid):
    u = current_user()
    if u["role"] != "admin":
        return "Forbidden", 403
    db = get_db()
    db.execute("DELETE FROM appointments WHERE id=?", (aid,))
    db.commit()
    return redirect("/admin")

@app.route("/patient", methods=["GET", "POST"])
@login_required
def patient():
    u = current_user()
    if u["role"] != "patient":
        return "Forbidden", 403
    db = get_db()
    if request.method == "POST":
        doctor_id = request.form.get("doc_id")
        date = request.form.get("date")
        doctor = db.execute("SELECT availability FROM doctors WHERE id=?", (doctor_id,)).fetchone()
        if doctor and doctor["availability"] == "Available" and date:
            db.execute(
                "INSERT INTO appointments(patient_id,doctor_id,date) VALUES (?,?,?)",
                (u["id"], doctor_id, date),
            )
            db.commit()
    docs = db.execute("SELECT * FROM doctors WHERE availability='Available'").fetchall()
    apps_ = db.execute(
        """SELECT appointments.*, doctors.name 
           FROM appointments JOIN doctors ON doctor_id=doctors.id 
           WHERE patient_id=?""",
        (u["id"],),
    ).fetchall()
    return render_template("patient_dashboard.html", docs=docs, apps=apps_)

@app.route("/doctor", methods=["GET", "POST"])
@login_required
def doctor():
    u = current_user()
    if u["role"] != "doctor":
        return "Forbidden", 403
    db = get_db()
    today = datetime.now().strftime("%Y-%m-%d")
    # Handle diagnosis/treatment note submission
    if request.method == "POST":
        appointment_id = request.form.get("appointment_id")
        diagnosis = request.form.get("diagnosis", "").strip()
        notes = request.form.get("notes", "").strip()
        # Add columns if not exist
        try:
            db.execute("ALTER TABLE appointments ADD COLUMN diagnosis TEXT")
            db.execute("ALTER TABLE appointments ADD COLUMN notes TEXT")
            db.commit()
        except sqlite3.OperationalError:
            pass  # columns already exist
        db.execute(
            "UPDATE appointments SET diagnosis=?, notes=? WHERE id=? AND doctor_id=?",
            (diagnosis, notes, appointment_id, u["id"])
        )
        db.commit()
    apps_ = db.execute(
        """SELECT appointments.*, users.username 
           FROM appointments JOIN users ON patient_id=users.id 
           WHERE doctor_id=? AND date>=?
           ORDER BY date ASC""",
        (u["id"], today),
    ).fetchall()
    return render_template("doctor_dashboard.html", apps=apps_)

@app.route("/doctor/done/<int:aid>", methods=["POST", "GET"])
@login_required
def doc_done(aid):
    u = current_user()
    if u["role"] != "doctor":
        return "Forbidden", 403
    db = get_db()
    if request.method == "POST":
        diagnosis = request.form.get("diagnosis", "").strip()
        notes = request.form.get("notes", "").strip()
        # Add columns if not exist
        try:
            db.execute("ALTER TABLE appointments ADD COLUMN diagnosis TEXT")
            db.execute("ALTER TABLE appointments ADD COLUMN notes TEXT")
            db.commit()
        except sqlite3.OperationalError:
            pass
        db.execute(
            "UPDATE appointments SET status='Completed', diagnosis=?, notes=? WHERE id=? AND doctor_id=?",
            (diagnosis, notes, aid, u["id"])
        )
        db.commit()
        return redirect("/doctor")
    # GET: Show form for diagnosis/notes
    appt = db.execute(
        """SELECT appointments.*, users.username 
           FROM appointments JOIN users ON patient_id=users.id 
           WHERE appointments.id=? AND doctor_id=?""",
        (aid, u["id"])
    ).fetchone()
    if not appt:
        return "Appointment not found", 404
    return render_template("doctor_mark_complete.html", appt=appt)

@app.route("/register_doctor", methods=["GET", "POST"])
def register_doctor():
    if request.method == "POST":
        u = request.form.get("u")
        p = request.form.get("p")
        name = request.form.get("name")
        spec = request.form.get("spec")
        if not u or not p or not name or not spec:
            return render_template("register_doctor.html", err="All fields required")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users(username,password,role) VALUES (?,?,?)",
                (u, hash_pwd(p), "doctor"),
            )
            db.commit()
            user_id = db.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone()["id"]
            db.execute(
                "INSERT INTO doctors(id, name, specialization, availability) VALUES (?, ?, ?, ?)",
                (user_id, name, spec, "Available"),
            )
            db.commit()
            return redirect("/login")
        except sqlite3.IntegrityError:
            return render_template("register_doctor.html", err="Username taken")
    return render_template("register_doctor.html", err=None)

# Admin can assign doctor credentials
@app.route("/admin/add_doctor", methods=["GET", "POST"])
@login_required
def add_doctor():
    u = current_user()
    if u["role"] != "admin":
        return "Forbidden", 403
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        spec = request.form.get("spec", "").strip()
        doc_user = request.form.get("doc_user", "").strip()
        doc_pass = request.form.get("doc_pass", "").strip()
        if not name or not spec or not doc_user or not doc_pass:
            doc_creds = db.execute(
                """SELECT dc.id, d.name, dc.username, dc.password
                   FROM doctor_credentials dc
                   JOIN doctors d ON dc.doctor_id = d.id"""
            ).fetchall()
            return render_template("add_doctor.html", err="All fields required", doc_creds=doc_creds)
        try:
            db.execute(
                "INSERT INTO doctors(name, specialization, availability) VALUES (?, ?, ?)",
                (name, spec, "Available"),
            )
            db.commit()
            doctor_id = db.execute("SELECT id FROM doctors WHERE name=? AND specialization=?", (name, spec)).fetchone()["id"]
            db.execute(
                "INSERT INTO doctor_credentials(doctor_id, username, password) VALUES (?, ?, ?)",
                (doctor_id, doc_user, hash_pwd(doc_pass)),
            )
            db.execute(
                "INSERT INTO users(username, password, role) VALUES (?, ?, ?)",
                (doc_user, hash_pwd(doc_pass), "doctor"),
            )
            db.commit()
        except sqlite3.IntegrityError:
            doc_creds = db.execute(
                """SELECT dc.id, d.name, dc.username, dc.password
                   FROM doctor_credentials dc
                   JOIN doctors d ON dc.doctor_id = d.id"""
            ).fetchall()
            return render_template("add_doctor.html", err="Username already exists", doc_creds=doc_creds)
    doc_creds = db.execute(
        """SELECT dc.id, d.name, dc.username, dc.password
           FROM doctor_credentials dc
           JOIN doctors d ON dc.doctor_id = d.id"""
    ).fetchall()
    return render_template("add_doctor.html", err=None, doc_creds=doc_creds)

# ---------- Run ----------
if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        with app.app_context():
            init_db()
    app.run(debug=True)