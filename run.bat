@echo off
REM Local development launcher. DEBUG defaults to False (production-safe),
REM so enable it explicitly for local runs.
set DJANGO_DEBUG=True
python manage.py runserver
pause
