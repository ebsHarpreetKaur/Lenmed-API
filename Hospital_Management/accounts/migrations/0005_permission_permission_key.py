# Generated by Django 4.2.3 on 2023-07-31 06:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_remove_role_role_key'),
    ]

    operations = [
        migrations.AddField(
            model_name='permission',
            name='permission_key',
            field=models.CharField(default=None, max_length=50, null=True, unique=True),
        ),
    ]
