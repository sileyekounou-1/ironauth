def verification_email(email: str, verification_url: str, app_name: str = "IronAuth") -> str:
    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #333;">Vérifiez votre adresse email</h2>
  <p>Bonjour,</p>
  <p>Merci de vous être inscrit sur <strong>{app_name}</strong>. Cliquez sur le bouton ci-dessous pour vérifier votre adresse email.</p>
  <div style="text-align: center; margin: 30px 0;">
    <a href="{verification_url}"
       style="background-color: #e65c00; color: white; padding: 14px 28px;
              text-decoration: none; border-radius: 6px; font-size: 16px;">
      Vérifier mon email
    </a>
  </div>
  <p style="color: #666; font-size: 14px;">Ce lien expire dans 24 heures.</p>
  <p style="color: #666; font-size: 14px;">Si vous n'avez pas créé de compte, ignorez cet email.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
  <p style="color: #999; font-size: 12px;">{app_name} — Propulsé par IronAuth</p>
</body>
</html>
"""


def reset_password_email(email: str, reset_url: str, app_name: str = "IronAuth") -> str:
    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #333;">Réinitialisation de votre mot de passe</h2>
  <p>Bonjour,</p>
  <p>Vous avez demandé à réinitialiser votre mot de passe sur <strong>{app_name}</strong>.</p>
  <div style="text-align: center; margin: 30px 0;">
    <a href="{reset_url}"
       style="background-color: #e65c00; color: white; padding: 14px 28px;
              text-decoration: none; border-radius: 6px; font-size: 16px;">
      Réinitialiser mon mot de passe
    </a>
  </div>
  <p style="color: #666; font-size: 14px;">Ce lien expire dans 1 heure.</p>
  <p style="color: #666; font-size: 14px;">Si vous n'avez pas fait cette demande, ignorez cet email — votre mot de passe reste inchangé.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
  <p style="color: #999; font-size: 12px;">{app_name} — Propulsé par IronAuth</p>
</body>
</html>
"""
