# Contributor Guide for Frontend Developers

Welcome to the **Penco** project! This guide is designed to help you—our frontend contributors—get started with the project. Even if you’re new to Django, this guide will explain the project structure and where to place your assets (images, CSS, JavaScript, etc.).

---

## 1. Project Overview

The project is built with Django and has the following structure:

```
pentour/
├── chat/
│   ├── templates/       # HTML templates (e.g., auth.html, index.html, chatbox.html)
│   ├── static/          # (Optional) App-specific static files can be placed here.
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── models.py
│   ├── serializers.py
│   ├── tests.py
│   ├── urls.py
│   └── views.py
├── client/
│   └── enc_test_keygen/ # Contains helper scripts (not relevant for frontend work)
├── pc/
│   ├── __init__.py
│   ├── asgi.py
│   ├── settings.py     # Contains configuration including static files settings
│   ├── urls.py
│   └── wsgi.py
└── manage.py           # Django’s command-line utility
```

---

## 2. Working with Static Files

### What Are Static Files?

Static files are assets (images, CSS, JavaScript, fonts, etc.) that do not change dynamically with each request. Django uses its staticfiles framework to manage these files.

### Where to Place Your Assets

There are two common approaches:

### A. App-Level Static Directories

For assets specific to an app (like chat-related images or styles):

1. **Create a Static Folder in the App:**  
   Inside the **chat** app, create a directory structure like this:
   ```
   pentour/
     └── chat/
         ├── static/
         │   └── chat/
         │       ├── css/
         │       ├── js/
         │       └── images/
         └── templates/
   ```

2. **Reference in Templates:**  
   In your HTML templates (inside **chat/templates/**), load static files using Django’s static template tag:
   ```django
   {% load static %}
   <link rel="stylesheet" type="text/css" href="{% static 'chat/css/style.css' %}">
   <img src="{% static 'chat/images/logo.png' %}" alt="Logo">
   ```

### B. Global Static Directory

For assets shared across the entire project:

1. **Create a Global Static Folder:**  
   At the root of your project (next to `manage.py`), create a folder named `static/`:
   ```
   pentour/
     ├── static/
     │   ├── css/
     │   ├── js/
     │   └── images/
     ├── chat/
     └── manage.py
   ```

2. **Ensure Settings Are Correct:**  
   In **pc/settings.py**, the static file settings should include:
   ```python
   STATIC_URL = '/static/'
   STATIC_ROOT = BASE_DIR / "staticfiles"
   ```
   - `STATIC_URL` is the URL path used to access static files.
   - `STATIC_ROOT` is where the `collectstatic` command will gather all static files for production.

3. **Reference in Templates:**  
   Use the same static template tag:
   ```django
   {% load static %}
   <link rel="stylesheet" href="{% static 'css/style.css' %}">
   <img src="{% static 'images/logo.png' %}" alt="Logo">
   ```

*Choose the method that fits best with our project’s needs. App-level static directories help keep assets modular, while a global static folder is useful if most assets are shared.*

---

## 3. Running and Testing the Project

### Local Development

- **Run the Server:**  
  Use the Django development server:
  ```bash
  python manage.py runserver
  ```
- **Static Files:**  
  With `DEBUG=True`, Django automatically serves static files.

### Production

- **Collect Static Files:**  
  Run:
  ```bash
  python manage.py collectstatic
  ```
  This gathers all static files into the directory specified by `STATIC_ROOT`.
- **Serving Static Files:**  
  In production, a web server like Nginx serves static files from `STATIC_ROOT`.

---

## 4. Git and Repository Guidelines

- **.gitignore:**  
  Our `.gitignore` file is set to ignore:
  - Virtual environment directories (e.g., `venv/`)
  - Local databases (e.g., `db.sqlite3`)
  - Environment files (e.g., `.env`)
  - IDE/editor directories (e.g., `.vscode/`, `.idea/`)
- **Commit Messages:**  
  Use clear, descriptive commit messages (e.g., "Add new CSS for chat interface", "Update logo image").
- **Branching:**  
  For new features or frontend changes, please create a separate branch and merge after review.

---

## 5. Getting Help

- **Documentation:**  
  Refer to the [Django documentation](https://docs.djangoproject.com/en/stable/) for backend details.
- **Team Support:**  
  If you have any questions, ask in our team channel. Your main work will be in the `templates/` and `static/` directories.
- **Development Workflow:**  
  Frontend changes (HTML, CSS, JavaScript, images) are typically made in the `chat/templates/` and either the `chat/static/chat/` or the global `static/` directory, depending on where assets are managed.

---

Happy coding and thank you for contributing to the project!

