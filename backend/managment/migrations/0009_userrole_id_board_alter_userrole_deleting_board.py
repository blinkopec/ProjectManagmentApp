# Generated by Django 5.0.3 on 2024-04-30 08:54

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('managment', '0008_userrole_commenting_userrole_creating_block_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='userrole',
            name='id_board',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='roles', to='managment.board'),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='userrole',
            name='deleting_board',
            field=models.BooleanField(default=True),
        ),
    ]