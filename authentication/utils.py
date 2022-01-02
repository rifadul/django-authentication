from django.contrib.auth.tokens import PasswordResetTokenGenerator

class TokenGenerator(PasswordResetTokenGenerator):
    pass


generate_tokens =TokenGenerator()