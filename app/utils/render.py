from fastapi import Request
from fastapi.templating import Jinja2Templates

def render_form_error(
    templates: Jinja2Templates,
    request: Request,
    template_name: str,
    message: str,
    status_code: int = 400,
    **context
):
    context.update({
        "request": request,
        "error": message,
    })

    return templates.TemplateResponse(
        template_name,
        context,
        status_code=status_code,
    )
