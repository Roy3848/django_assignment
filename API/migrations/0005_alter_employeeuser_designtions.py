# Generated by Django 4.0.5 on 2022-06-28 05:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('API', '0004_alter_employeeuser_designtions'),
    ]

    operations = [
        migrations.AlterField(
            model_name='employeeuser',
            name='designtions',
            field=models.CharField(choices=[('Analyst', 'Analyst'), ('Software Engineer', 'Software Engineer'), ('Trainee Engineer', 'Trainee Engineer')], default='Emplyee', max_length=30),
        ),
    ]