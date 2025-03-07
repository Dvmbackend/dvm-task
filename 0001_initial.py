# Generated by Django 5.1.6 on 2025-02-10 07:54

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Bus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bus_type', models.CharField(choices=[('Standard', 'Standard class'), ('Executive', 'Executive class'), ('Sleeper', 'Sleeper class')], max_length=20)),
                ('pickup_location', models.CharField(max_length=100)),
                ('destination_location', models.CharField(max_length=100)),
                ('date', models.DateField()),
                ('available_seats', models.IntegerField()),
            ],
        ),
    ]
