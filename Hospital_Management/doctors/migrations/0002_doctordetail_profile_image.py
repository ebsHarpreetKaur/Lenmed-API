# Generated by Django 4.2.3 on 2023-08-01 06:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('doctors', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='doctordetail',
            name='profile_image',
            field=models.TextField(blank=True, null=True),
        ),
    ]
