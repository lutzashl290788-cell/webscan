---
name: Bug report
about: Сообщите о проблеме, шаги для воспроизведения и ожидаемое поведение
title: "[BUG] "
labels: bug
assignees: ''
---

## Описание проблемы

Кратко опишите, что пошло не так.

## Шаги для воспроизведения
1. 
2. 
3. 

## Ожидаемое поведение

Опишите ожидаемый результат.

## Логи / вывод

Прикрепите релевантные логи, трассировки или вывод pytest (если ошибка теста).

## Среда
- OS: 
- Python: 
- Версия webscan: 
---
name: Bug report
about: Something is broken or behaving unexpectedly
title: "bug: <short description>"
labels: bug
assignees: ""
---

## What happened

<!-- A clear description of the bug. What did you do, and what went wrong? -->

## Expected behaviour

<!-- What should have happened instead? -->

## Steps to reproduce

```bash
# Paste the exact command(s) you ran
webscan -t https://example.com ...
```

<!-- If the target is not publicly reachable, describe the response or paste
     relevant headers / output that you can share safely. -->

## Actual output / error

```
Paste the full CLI output or stack trace here.
```

## Environment

| Field | Value |
|---|---|
| WebScan version | <!-- run: webscan --version --> |
| Python version | <!-- run: python --version --> |
| OS | <!-- e.g. Ubuntu 22.04, macOS 14, Windows 11 --> |
| Install method | <!-- pip install webscan / pip install -e ".[dev]" / other --> |

## Additional context

<!-- Screenshots, related issues, or any other information that may help. -->
