# Generated by Django 5.0.3 on 2024-05-11 04:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('managment', '0011_userrole_edit_member_role'),
    ]

    operations = [
        migrations.RenameField(
            model_name='userrole',
            old_name='edit_member_role',
            new_name='edit_members',
        ),
    ]
