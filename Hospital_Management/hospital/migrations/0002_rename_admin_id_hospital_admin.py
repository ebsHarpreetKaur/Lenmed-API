# Generated by Django 4.2.3 on 2023-07-06 08:08

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('hospital', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='hospital',
            old_name='admin_id',
            new_name='admin',
        ),
    ]
