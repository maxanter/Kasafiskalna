from .models import User
from django.db import connection

# Sprawdź czy użytkownik ma odpowiednie uprawnienia
# requier_perms - lista wymaganych uprawnień
def check_perms(id, requier_perms):
    user = User.objects.get(id = id)
    # Sprawdź czy użytkownik posiada uprawnienia w modelu używając predefiniowanej funkcji django
    has_permision = user.has_perms(requier_perms)
    if has_permision:
        return True
    # Sprawdź, czy uzytkownik posiada uprawnienia w bazie danych
    try:
        with connection.cursor() as cursor:
            # Sprawdź, czy użytkownik ma co najmniej jedno z wymaganych uprawnień
            for kod_uprawnienia in requier_perms:
                # Sprawdź uprawnienie indywidualnie
                cursor.execute(
                    "SELECT * FROM auth_permission "
                    "WHERE codename = %s",
                    [kod_uprawnienia]
                )
                permission_result = cursor.fetchone()

                if permission_result:
                    # Sprawdź, czy użytkownik ma to uprawnienie
                    cursor.execute(
                        "SELECT * FROM kfp_user_user_permissions "
                        "WHERE user_id = %s AND permission_id = %s",
                        [id, permission_result[0]]
                    )
                    user_has_permission = cursor.fetchone()

                    if user_has_permission:
                        return True

                # Sprawdź, czy użytkownik należy do grupy posiadającej to uprawnienie
                cursor.execute(
                    "SELECT * FROM auth_group "
                    "INNER JOIN kfp_user_groups ON auth_group.id = kfp_user_groups.group_id "
                    "INNER JOIN auth_group_permissions ON auth_group.id = auth_group_permissions.group_id "
                    "WHERE kfp_user_groups.user_id = %s AND auth_group_permissions.permission_id = %s",
                    [id, permission_result[0]]
                )
                group_has_permission = cursor.fetchone()

                if group_has_permission:
                    return True

            return False
    # Jeżeli coś poszło nie tak, zwróć błąd jako false
    except Exception:
        return False