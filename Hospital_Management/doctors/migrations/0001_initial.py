# Generated by Django 4.2.3 on 2023-07-28 07:56

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='DoctorDetail',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('modified_at', models.DateTimeField(auto_now=True, verbose_name='Updated')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('phone_number', models.IntegerField()),
                ('gender', models.CharField(choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], max_length=20)),
                ('specialization', models.CharField(max_length=100)),
                ('doctor', models.ForeignKey(default=None, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
