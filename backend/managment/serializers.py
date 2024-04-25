from rest_framework import serializers
from .models import  User, StatusTask, UserRole, UserBoard, Board, Comment,Block,Task


class DynamicFieldsCategorySerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        fields = kwargs.pop('fields', None)
        super().__init__(*args, **kwargs)

        if fields is not None:
            allowed = set(fields)
            existing = set(self.fields)
            for field_name in existing - allowed:
                self.fields.pop(field_name)


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ('id', 'id_user', 'text', 'description', 'id_task')

class UserBoardSerializer(DynamicFieldsCategorySerializer):
    class Meta:
        model = UserBoard
        fields = ('id','id_user', 'id_board', 'id_user_role')
    

class BoardSerializer(serializers.ModelSerializer):
    users = UserBoardSerializer(many=True, fields=['id_user', 'id_user_role'], required=False)
    
    class Meta:
        model = Board
        fields = ('id', 'name', 'users')


class ExtUserSerializer(serializers.ModelSerializer):
    boards = UserBoardSerializer(many=True, fields=['id_board', 'id_user_role'], required=False)
    comments = serializers.PrimaryKeyRelatedField(many=True, read_only=True, required=False)
    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name', 'email', 'boards', 'comments')

class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username' , 'first_name', 'last_name', 'email')

class UserSerializer(serializers.ModelSerializer):
    boards = UserBoardSerializer(many=True, fields=['id_board', 'id_user_role'], required=False)
    comments = serializers.PrimaryKeyRelatedField(many=True, read_only=True, required=False)
    class Meta:
        model = User
        fields = ('id', 'password', 'last_login', 'is_superuser', 'username', 'first_name', 'last_name', 'email', 'date_joined', 'is_active', 'is_staff', 'boards', 'comments')


class TaskSerializer(serializers.ModelSerializer):
    comments = serializers.PrimaryKeyRelatedField(many=True, read_only=True, required=False)
    class Meta:
        model = Task
        fields = ('id', 'id_block', 'id_status_task', 'text', 'description', 'date', 'comments')


class BlockSerializer(serializers.ModelSerializer):
    tasks = serializers.PrimaryKeyRelatedField(many=True, read_only=True, required=False)
    class Meta:
        model = Block
        fields = ('id', 'name', 'position', 'id_board', 'tasks')




class StatusTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = StatusTask
        fields = ('id','name')

class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = ('id','name')

