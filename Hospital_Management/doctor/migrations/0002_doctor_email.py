# Generated by Django 4.2.3 on 2023-07-26 11:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('doctor', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='doctor',
            name='email',
            field=models.EmailField(max_length=254, null=True, unique=True, verbose_name='email'),
        ),
    ]
