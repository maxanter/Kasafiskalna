"""

def check_perms(id, requier_perms):
    user = User.objects.get(id = id)
    has_permision = user.has_perms(requier_perms)
    return has_permision
"""

from .models import User
from django.db import connection

def check_perms(id, requier_perms):
    user = User.objects.get(id = id)
    has_permision = user.has_perms(requier_perms)
    if has_permision:
        return True
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
                print(f"Permission Result: {permission_result}")

                if permission_result:
                    # Sprawdź, czy użytkownik ma to uprawnienie indywidualnie
                    cursor.execute(
                        "SELECT * FROM kfp_user_user_permissions "
                        "WHERE user_id = %s AND permission_id = %s",
                        [id, permission_result[0]]
                    )
                    user_has_permission = cursor.fetchone()
                    print(f"User Has Permission: {user_has_permission}")

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
                print(f"Group Has Permission: {group_has_permission}")

                if group_has_permission:
                    return True

            return False
    except Exception as e:
        print(f"Błąd: {e}")
        return False