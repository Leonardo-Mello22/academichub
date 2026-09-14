import os

from flask import (
    Blueprint,
    render_template,
    request,
    session,
    redirect,
    url_for,
)

from google import genai

from app.database import query_db


assistant_bp = Blueprint(
    "assistant",
    __name__
)


MODEL_NAME = "gemini-3.6-flash"


def require_login():
    if not session.get("user_id"):
        return redirect(
            url_for("auth.login")
        )

    return None


def get_student_context(user_id):
    user = query_db(
        """
        SELECT
            full_name,
            student_id,
            gpa
        FROM users
        WHERE id = %s
        """,
        (user_id,),
        one=True,
    )

    if not user:
        return None

    courses = query_db(
        """
        SELECT
            c.code,
            c.name
        FROM enrollments e
        JOIN courses c
            ON e.course_id = c.id
        WHERE e.student_id = %s
        ORDER BY c.code
        """,
        (user_id,),
    )

    grades = query_db(
        """
        SELECT
            c.code,
            c.name,
            g.assignment_name,
            g.grade,
            g.feedback
        FROM grades g
        JOIN courses c
            ON g.course_id = c.id
        WHERE g.student_id = %s
        ORDER BY
            c.code,
            g.created_at DESC
        """,
        (user_id,),
    )

    context = {
        "name": user[0],
        "student_id": user[1],
        "gpa": user[2],
        "courses": courses,
        "grades": grades,
    }

    return context


def format_context(context):
    lines = [
        "DADOS ACADÊMICOS DO ALUNO",
        "",
        f"Nome: {context['name']}",
        f"Matrícula: {context['student_id']}",
        f"IRA/GPA: {context['gpa']}",
        "",
        "DISCIPLINAS:",
    ]

    if context["courses"]:
        for code, name in context["courses"]:
            lines.append(
                f"- {code}: {name}"
            )
    else:
        lines.append(
            "- Nenhuma disciplina registrada."
        )

    lines.extend([
        "",
        "NOTAS:",
    ])

    if context["grades"]:
        for (
            code,
            course,
            assignment,
            grade,
            feedback,
        ) in context["grades"]:
            line = (
                f"- {code} | {course} | "
                f"{assignment}: {grade}"
            )

            if feedback:
                line += (
                    f" | Feedback: {feedback}"
                )

            lines.append(line)

    else:
        lines.append(
            "- Nenhuma nota registrada."
        )

    return "\n".join(lines)


def ask_gemini(question, context):
    api_key = os.environ.get(
        "GEMINI_API_KEY"
    )

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY não configurada."
        )

    client = genai.Client(
        api_key=api_key
    )

    academic_context = format_context(
        context
    )

    prompt = f"""
Você é o Assistente Acadêmico do AcademicHub.

Sua função é ajudar o aluno a compreender
seu próprio desempenho acadêmico.

Regras:
- Responda em português brasileiro.
- Utilize somente os dados fornecidos abaixo.
- Não invente disciplinas, notas ou informações.
- Caso a pergunta não possa ser respondida
  com os dados disponíveis, informe isso.
- Seja objetivo e claro.
- Você pode resumir o desempenho,
  identificar pontos de atenção e sugerir
  estratégias gerais de estudo.
- Não trate suas sugestões como avaliação
  oficial da instituição.

CONTEXTO DO ALUNO:

{academic_context}

PERGUNTA DO ALUNO:

{question}
"""

    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
    )

    if not response.text:
        raise RuntimeError(
            "A IA não retornou uma resposta."
        )

    return response.text.strip()


@assistant_bp.route(
    "/assistente",
    methods=["GET", "POST"],
)
def assistant():
    redir = require_login()

    if redir:
        return redir

    answer = None
    error = None
    question = ""

    role = session.get(
        "role",
        "aluno"
    )

    if role != "aluno":
        return render_template(
            "assistant/index.html",
            error=(
                "O assistente acadêmico está "
                "disponível apenas para alunos."
            ),
            answer=None,
            question="",
        )

    if request.method == "POST":
        question = request.form.get(
            "question",
            ""
        ).strip()

        if not question:
            error = (
                "Digite uma pergunta para "
                "o assistente."
            )

        elif len(question) > 1000:
            error = (
                "A pergunta deve possuir "
                "no máximo 1000 caracteres."
            )

        else:
            try:
                context = get_student_context(
                    session["user_id"]
                )

                if not context:
                    error = (
                        "Não foi possível localizar "
                        "seus dados acadêmicos."
                    )

                else:
                    answer = ask_gemini(
                        question,
                        context,
                    )

            except Exception as exc:
                print(
                    "[AcademicHub AI]",
                    repr(exc)
                )

                error = (
                    "Não foi possível consultar "
                    "o assistente no momento."
                )

    return render_template(
        "assistant/index.html",
        answer=answer,
        error=error,
        question=question,
    )
