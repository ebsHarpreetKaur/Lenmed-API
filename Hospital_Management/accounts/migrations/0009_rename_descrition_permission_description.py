# Generated by Django 4.2.3 on 2023-08-07 06:34

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0008_permission_descrition'),
    ]

    operations = [
        migrations.RenameField(
            model_name='permission',
            old_name='descrition',
            new_name='description',
        ),
    ]
