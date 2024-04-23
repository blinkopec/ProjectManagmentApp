from django.contrib import admin
from .models import User, Block, Board, Comment, StatusTask, Task, UserRole, UserBoard 

# Register your models here.

admin.site.register(Block)
admin.site.register(Board)
admin.site.register(Comment)
admin.site.register(User)
admin.site.register(StatusTask)
admin.site.register(Task)
admin.site.register(UserRole)
admin.site.register(UserBoard)
