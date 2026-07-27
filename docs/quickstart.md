# Quickstart

Установка и быстрый запуск локально:

```bash
git clone https://github.com/lutzashl290788-cell/webscan
cd webscan
python -m pip install --upgrade pip
python -m pip install -e .

# Запуск сканирования (пример):
webscan -t https://example.com --safe-mode
```

Запуск тестов локально:

```bash
python -m pip install -e .
python -m pip install pytest
pytest -q
```

Если нужен CI — в репозитории добавлен пример GitHub Actions workflow.
