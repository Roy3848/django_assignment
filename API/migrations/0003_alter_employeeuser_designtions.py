# Generated by Django 4.0.5 on 2022-06-19 18:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('API', '0002_employeeuser_is_manager_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='employeeuser',
            name='designtions',
            field=models.CharField(choices=[('Engineer', 'Engineer'), ('Associate Engineer', 'Associate Engineer'), ('Trainee Engineer', 'Trainee Engineer')], default='Emplyee', max_length=30),
        ),
    ]
