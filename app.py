import csv
import io
import logging
import math
import os
import secrets
import sqlite3
import time
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CENV_PATH = os.path.join(BASE_DIR, ".env")
CATEGORIAS = {
    "bullying": "Bullying",
    "assedio": "Assédio",
    "violencia": "Violência",
    "corrupcao": "Corrupção",
    "outros": "Outros",
}
STATUS_VALIDOS = {"pendente", "resolvido"}
MAX_MENSAGEM = 2000
ITENS_POR_PAGINA = 10
LOGIN_MAX_TENTATIVAS = 5
LOGIN_BLOQUEIO_SEGUNDOS = 300


def carregar_env_ficheiro(path):
    if not os.path.exists(path):
        return

    with open(path, encoding="utf-8") as env_file:
        for linha in env_file:
            linha = linha.strip()
            if not linha or linha.startswith("#") or "=" not in linha:
                continue

            chave, valor = linha.split("=", 1)
            chave = chave.strip()
            valor = valor.strip().strip("\"'")
            os.environ.setdefault(chave, valor)


carregar_env_ficheiro(CENV_PATH)


DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "denuncias.db"))


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["ADMIN_PASSWORD"] = os.environ.get("ADMIN_PASSWORD")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


def conectar_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def criar_tabela():
    with conectar_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS denuncias (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                categoria TEXT NOT NULL,
                mensagem TEXT NOT NULL,
                data TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'pendente'
            )
            """
        )


def gerar_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = gerar_csrf_token
app.jinja_env.globals["categorias_disponiveis"] = CATEGORIAS


def validar_csrf():
    token_sessao = session.get("csrf_token")
    token_form = request.form.get("csrf_token")
    if not token_sessao or not token_form or token_sessao != token_form:
        abort(400, "Token CSRF inválido.")


def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin"):
            flash("Inicia sessão para aceder ao painel.", "erro")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


def normalizar_categoria(valor):
    categoria = (valor or "").strip().lower()
    return categoria if categoria in CATEGORIAS else ""


def normalizar_status(valor):
    status = (valor or "").strip().lower()
    return status if status in STATUS_VALIDOS else ""


def mensagem_login_bloqueado():
    bloqueado_ate = session.get("login_lock_until", 0)
    segundos = max(0, int(bloqueado_ate - time.time()))
    minutos = max(1, math.ceil(segundos / 60))
    return f"Login temporariamente bloqueado. Tenta novamente em cerca de {minutos} minuto(s)."


def login_bloqueado():
    return time.time() < session.get("login_lock_until", 0)


def registar_falha_login():
    tentativas = session.get("login_attempts", 0) + 1
    session["login_attempts"] = tentativas
    if tentativas >= LOGIN_MAX_TENTATIVAS:
        session["login_lock_until"] = time.time() + LOGIN_BLOQUEIO_SEGUNDOS
        session["login_attempts"] = 0


def limpar_estado_login():
    session.pop("login_attempts", None)
    session.pop("login_lock_until", None)


def obter_denuncias(filtro_status="", filtro_categoria="", pesquisa=""):
    clausulas = []
    parametros = []

    if filtro_status:
        clausulas.append("status = ?")
        parametros.append(filtro_status)

    if filtro_categoria:
        clausulas.append("categoria = ?")
        parametros.append(filtro_categoria)

    if pesquisa:
        clausulas.append("(mensagem LIKE ? OR categoria LIKE ?)")
        termo = f"%{pesquisa}%"
        parametros.extend([termo, termo])

    where_sql = f"WHERE {' AND '.join(clausulas)}" if clausulas else ""
    return where_sql, parametros


def obter_resumo(conn):
    totais = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'pendente' THEN 1 ELSE 0 END) AS pendentes,
            SUM(CASE WHEN status = 'resolvido' THEN 1 ELSE 0 END) AS resolvidos
        FROM denuncias
        """
    ).fetchone()

    categorias = conn.execute(
        """
        SELECT categoria, COUNT(*) AS total
        FROM denuncias
        GROUP BY categoria
        ORDER BY total DESC, categoria ASC
        """
    ).fetchall()

    return {
        "total": totais["total"] or 0,
        "pendentes": totais["pendentes"] or 0,
        "resolvidos": totais["resolvidos"] or 0,
        "categorias": categorias,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/denuncia", methods=["POST"])
def denuncia():
    validar_csrf()

    categoria = normalizar_categoria(request.form.get("categoria"))
    mensagem = (request.form.get("mensagem") or "").strip()

    if not categoria or not mensagem:
        flash("Preenche todos os campos obrigatórios.", "erro")
        return redirect(url_for("index"))

    if len(mensagem) < 12:
        flash("Descreve um pouco melhor o ocorrido para podermos analisar a situação.", "erro")
        return redirect(url_for("index"))

    if len(mensagem) > MAX_MENSAGEM:
        flash(f"A mensagem não pode ultrapassar {MAX_MENSAGEM} caracteres.", "erro")
        return redirect(url_for("index"))

    try:
        with conectar_db() as conn:
            conn.execute(
                "INSERT INTO denuncias (categoria, mensagem) VALUES (?, ?)",
                (categoria, mensagem),
            )

        flash("Denúncia enviada com sucesso.", "sucesso")
    except sqlite3.Error:
        flash("Não foi possível registar a denúncia. Tenta novamente.", "erro")

    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        validar_csrf()

        if login_bloqueado():
            flash(mensagem_login_bloqueado(), "erro")
            return redirect(url_for("login"))

        senha = request.form.get("senha") or ""
        senha_admin = app.config.get("ADMIN_PASSWORD")

        if not senha_admin:
            return render_template(
                "login.html",
                erro="A variável de ambiente ADMIN_PASSWORD não está configurada.",
            ), 500

        if secrets.compare_digest(senha, senha_admin):
            session.clear()
            session["admin"] = True
            gerar_csrf_token()
            limpar_estado_login()
            flash("Sessão iniciada com sucesso.", "sucesso")
            return redirect(url_for("painel"))

        registar_falha_login()
        if login_bloqueado():
            flash(mensagem_login_bloqueado(), "erro")
        else:
            restantes = LOGIN_MAX_TENTATIVAS - session.get("login_attempts", 0)
            flash(f"Senha incorreta. Restam {restantes} tentativa(s).", "erro")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/painel")
@admin_required
def painel():
    pesquisa = (request.args.get("q") or "").strip()
    filtro_status = normalizar_status(request.args.get("status"))
    filtro_categoria = normalizar_categoria(request.args.get("categoria"))
    pagina = max(1, request.args.get("page", default=1, type=int))
    offset = (pagina - 1) * ITENS_POR_PAGINA

    with conectar_db() as conn:
        where_sql, parametros = obter_denuncias(filtro_status, filtro_categoria, pesquisa)
        total = conn.execute(
            f"SELECT COUNT(*) AS total FROM denuncias {where_sql}",
            parametros,
        ).fetchone()["total"]
        total_paginas = max(1, math.ceil(total / ITENS_POR_PAGINA)) if total else 1
        pagina = min(pagina, total_paginas)
        offset = (pagina - 1) * ITENS_POR_PAGINA
        denuncias = conn.execute(
            f"""
            SELECT id, categoria, mensagem, data, status
            FROM denuncias
            {where_sql}
            ORDER BY data DESC
            LIMIT ? OFFSET ?
            """,
            [*parametros, ITENS_POR_PAGINA, offset],
        ).fetchall()
        resumo = obter_resumo(conn)

    filtros = {
        "q": pesquisa,
        "status": filtro_status,
        "categoria": filtro_categoria,
    }

    return render_template(
        "painel.html",
        denuncias=denuncias,
        resumo=resumo,
        filtros=filtros,
        pagina=pagina,
        total_paginas=total_paginas,
        total_filtrado=total,
    )


@app.route("/estado/<int:denuncia_id>", methods=["POST"])
@admin_required
def alterar_estado(denuncia_id):
    validar_csrf()
    novo_estado = normalizar_status(request.form.get("status"))
    if not novo_estado:
        abort(400, "Estado inválido.")

    with conectar_db() as conn:
        conn.execute(
            "UPDATE denuncias SET status = ? WHERE id = ?",
            (novo_estado, denuncia_id),
        )

    flash("Estado atualizado com sucesso.", "sucesso")
    return redirect(url_for("painel", **request.args))


@app.route("/apagar/<int:denuncia_id>", methods=["POST"])
@admin_required
def apagar(denuncia_id):
    validar_csrf()

    with conectar_db() as conn:
        conn.execute("DELETE FROM denuncias WHERE id = ?", (denuncia_id,))

    flash("Denúncia apagada com sucesso.", "sucesso")
    return redirect(url_for("painel", **request.args))


@app.route("/exportar")
@admin_required
def exportar():
    pesquisa = (request.args.get("q") or "").strip()
    filtro_status = normalizar_status(request.args.get("status"))
    filtro_categoria = normalizar_categoria(request.args.get("categoria"))

    with conectar_db() as conn:
        where_sql, parametros = obter_denuncias(filtro_status, filtro_categoria, pesquisa)
        denuncias = conn.execute(
            f"""
            SELECT id, categoria, mensagem, data, status
            FROM denuncias
            {where_sql}
            ORDER BY data DESC
            """,
            parametros,
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Categoria", "Mensagem", "Data", "Estado"])
    for denuncia in denuncias:
        writer.writerow(
            [
                denuncia["id"],
                CATEGORIAS.get(denuncia["categoria"], denuncia["categoria"]),
                denuncia["mensagem"],
                denuncia["data"],
                denuncia["status"],
            ]
        )

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=denuncias.csv"
    return response


@app.route("/logout", methods=["POST"])
@admin_required
def logout():
    validar_csrf()
    session.clear()
    flash("Sessão terminada.", "sucesso")
    return redirect(url_for("login"))


@app.errorhandler(400)
def erro_400(error):
    return render_template("erro.html", codigo=400, mensagem=str(error.description)), 400


@app.errorhandler(404)
def erro_404(_error):
    return render_template("erro.html", codigo=404, mensagem="Página não encontrada."), 404


@app.errorhandler(413)
def erro_413(_error):
    return (
        render_template(
            "erro.html",
            codigo=413,
            mensagem="O conteúdo enviado é demasiado grande.",
        ),
        413,
    )


@app.errorhandler(500)
def erro_500(_error):
    return (
        render_template(
            "erro.html",
            codigo=500,
            mensagem="Ocorreu um erro interno. Tenta novamente dentro de instantes.",
        ),
        500,
    )


criar_tabela()


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=debug_mode)
