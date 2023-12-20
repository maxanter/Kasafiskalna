from django.apps import AppConfig


class KfpConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'kfp'

    """def ready(self):
        import kfp.signals"""