from django.contrib.auth.hashers import make_password
from rest_framework import serializers

from .models import Block, Board, Comment, StatusTask, Task, User, UserBoard, UserRole


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
        fields = ('id', 'id_user', 'id_board', 'id_user_role')


class BoardSerializer(serializers.ModelSerializer):
    users = UserBoardSerializer(
        many=True, fields=['id_user', 'id_user_role'], required=False
    )

    class Meta:
        model = Board
        fields = ('id', 'name', 'users')


class ExtUserSerializer(serializers.ModelSerializer):
    boards = UserBoardSerializer(
        many=True, fields=['id_board', 'id_user_role'], required=False
    )
    comments = serializers.PrimaryKeyRelatedField(
        many=True, read_only=True, required=False
    )

    class Meta:
        model = User
        fields = (
            'id',
            'username',
            'first_name',
            'last_name',
            'email',
            'boards',
            'comments',
        )


# Сериалайзер для обновления данных пользователя о себе
class UpdateUserSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    first_name = serializers.CharField(max_length=150)
    last_name = serializers.CharField(max_length=150)
    email = serializers.CharField(max_length=254)

    def update(self, instance, validated_data):
        instance.email = validated_data.get('email', instance.email)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username', instance.username)
        instance.save()
        return instance

    def validate(self, data):
        if (
            'email' not in data
            and 'first_name' not in data
            and 'last_name' not in data
            and 'username' not in data
        ):
            raise serializers.ValidationError('No fields to update')
        return data


class UserSerializer(serializers.ModelSerializer):
    boards = UserBoardSerializer(
        many=True, fields=['id_board', 'id_user_role'], required=False
    )
    comments = serializers.PrimaryKeyRelatedField(
        many=True, read_only=True, required=False
    )

    class Meta:
        model = User
        fields = (
            'id',
            'password',
            'last_login',
            'is_superuser',
            'username',
            'first_name',
            'last_name',
            'email',
            'date_joined',
            'is_active',
            'is_staff',
            'boards',
            'comments',
        )

    def validate(self, data):
        if (
            'password' not in data
            and 'last_login' not in data
            and 'is_superuser' not in data
            and 'is_staff' not in data
            and 'is_active' not in data
            and 'date_joined' not in data
            and 'last_name' not in data
            and 'first_name' not in data
            and 'username' not in data
            and 'email' not in data
        ):
            raise serializers.ValidationError('No fields to update')

        if 'password' in data:
            data['password'] = make_password(data['password'])
        return data


class TaskSerializer(serializers.ModelSerializer):
    comments = serializers.PrimaryKeyRelatedField(
        many=True, read_only=True, required=False
    )

    class Meta:
        model = Task
        fields = (
            'id',
            'id_block',
            'id_status_task',
            'text',
            'description',
            'date',
            'comments',
        )


class BlockSerializer(serializers.ModelSerializer):
    tasks = serializers.PrimaryKeyRelatedField(
        many=True, read_only=True, required=False
    )

    class Meta:
        model = Block
        fields = ('id', 'name', 'position', 'id_board', 'tasks')


class StatusTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = StatusTask
        fields = ('id', 'name')


class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = (
            'id',
            'name',
            'id_board',
            'commenting',
            'deleting_board',
            'creating_task',
            'editing_task',
            'deleting_task',
            'creating_block',
            'editing_block',
            'deleting_block',
            'creating_status_task',
            'editing_status_task',
            'deleting_status_task',
            'creating_role',
            'editing_role',
            'deleting_role',
        )

    # def validate(self, data):
    #     if 'id_board' not in data:
    #         return serializers.ValidationError('id_board is required')
    #     return data

