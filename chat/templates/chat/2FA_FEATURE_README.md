# Two-Factor Authentication (2FA) Setup

This document explains how to enable and configure TOTP-based 2FA for your Django chat app.

## Dependencies

Install the following Python packages:

```bash
pip install pyotp qrcode pillow
```

- **pyotp**: Generates and verifies TOTP codes.  
- **qrcode**: Generates QR code images for provisioning.  
- **Pillow**: Imaging backend required by `qrcode` for PNG generation.

## Code Changes

1. **Add fields to your User model** (`chat/models.py`):

   ```python
   totp_secret = models.CharField(max_length=32, blank=True, null=True)
   is_2fa_enabled = models.BooleanField(default=False)
   ```

2. **Add the 2FA setup view** in `chat/views.py` and route it:

   ```python
   path('2fa/setup/', setup_2fa, name='setup_2fa'),
   ```

## Database Migrations

After modifying your `User` model, run:

```bash
python manage.py makemigrations chat
python manage.py migrate
```

## Testing Flow

1. Log in and click **Activate 2FA** in the User Menu.  
2. Scan the QR code with Google Authenticator.  
3. Enter the generated code to verify and enable 2FA.  
4. On next login, the credentials endpoint will require an `otp_code` field.
