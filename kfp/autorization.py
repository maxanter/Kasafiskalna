from .models import User

def check_perms(id, requier_perms):
    user = User.objects.get(id = id)
    has_permision = user.has_perms(requier_perms)
    return has_permision