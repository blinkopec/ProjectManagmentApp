from collections.abc import Iterable
from http.client import INSUFFICIENT_STORAGE
from operator import truediv
from typing import TypeGuard, reveal_type

from django.contrib.auth.password_validation import re
from django.db.models.fields import return_None
from django.db.models.fields.related import resolve_relation
from django.db.models.functions import TruncYear
from django.db.models.query import FlatValuesListIterable
from django.middleware.csrf import is_same_domain
from django.urls import register_converter
from django.utils.encoding import repercent_broken_unicode
from rest_framework import permissions

from .models import Block, Board, Comment, StatusTask, UserBoard, UserRole


class ReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS


class IsAdminOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        if request.user.is_staff:
            return True

        return bool(request.user and request.user.is_superuser)


class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        if request.method in permissions.SAFE_METHODS:
            return True

        return obj.id_user == request.user


class IsUserOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        if request.method in permissions.SAFE_METHODS:
            return True

        return obj.id == request.user.id


class IsUserRelateToBoardOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        if not request.user.is_authenticated:
            return False

        if request.method in permissions.SAFE_METHODS:
            return True

        user_board = (
            UserBoard.objects.select_related('id_user_role')
            .filter(id_user=request.user, id_board=obj.id)
            .first()
        )
        if user_board:
            if user_board.is_admin:
                return True

            if request.method == 'DELETE':
                if user_board.id_user_role.deleting_board:
                    return True
                return False

            if request.method == 'PATCH' or request.method == 'PUT':
                if user_board.id_user_role.editing_board:
                    return True
                return False


class IsUserRelateToBlockOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            user_board = (
                UserBoard.objects.select_related('id_user_role')
                .filter(id_user=request.user.id, id_board=request.data['id_board'])
                .first()
            )

            if not user_board:
                return False

            if user_board.is_admin:
                return True

            if user_board.id_user_role.creating_block:
                return True

            return False

        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        if not request.user.is_authenticated:
            return False

        if request.method in permissions.SAFE_METHODS:
            return True

        user_board = (
            UserBoard.objects.select_related('id_user_role')
            .filter(id_user=request.user, id_board=obj.id_board)
            .first()
        )

        if user_board:

            if request.method == 'PUT':
                return False

            if user_board.is_admin:
                return True

            if request.method == 'DELETE':
                if user_board.id_user_role.deleting_block:
                    return True
                return False

            if request.method == 'PATCH':
                if user_board.id_user_role.editing_block:
                    if 'id_board' not in request.data:
                        return True
                return False


# Comment
# delete - разрешение на удаление своих комментариев, разрешение на удаление всех комментариев, is_admin, но нельзя удалять не из своей доски
# create - можно создавать с разрешением или is_admin, но нельзя создавать комментарии от имени другого пользователя или не в свою доску
# update - можно редактировать с разрешением и только свои комментарии, is_admin может редактировать только свои комментарии


# Task
# delete - с разрешением на удаление или is_admin
# create - с рарешением на создание или is_admin
# update - с разрешением на редактирование или is_admin (put разрешен), id_block должен быть из той же доски, id_status_task тоже
class IsUserRelateToTaskOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            block = (
                Block.objects.select_related('id_board')
                .filter(id=request.data.get('id_block'))
                .first()
            )
            if not block:
                return False

            user_board = (
                UserBoard.objects.select_related('id_user_role')
                .filter(id_user=request.user.id, id_board=block.id_board.id)
                .first()
            )

            if not user_board:
                return False

            status_task = (
                StatusTask.objects.select_related('id_board')
                .filter(id=request.data.get('id_status_task'))
                .first()
            )
            if status_task.id_board == block.id_board:

                if user_board.is_admin:
                    return True

                if user_board.id_user_role.creating_task:
                    return True

            return False

        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        if not request.user.is_authenticated:
            return False

        if request.method in permissions.SAFE_METHODS:
            return True

        user_board = (
            UserBoard.objects.select_related('id_user_role')
            .filter(id_user=request.user.id, id_board=obj.id_block.id_board.id)
            .first()
        )

        if not user_board:
            return False

        if request.method == 'PUT' or request.method == 'PATCH':
            if 'id_block' not in request.data and 'id_status_task' not in request.data:
                if user_board.id_user_role.editing_task:
                    return True
                if user_board.is_admin:
                    return True
            if 'id_block' in request.data and 'id_status_task' in request.data:
                block_check = (
                    Block.objects.select_related('id_board')
                    .filter(id=request.data.get('id_block'))
                    .first()
                )
                status_check = (
                    StatusTask.objects.select_related('id_board')
                    .filter(id=request.data.get('id_status_task'))
                    .first()
                )

                if (
                    block_check.id_board == obj.id_block.id_board
                    and status_check.id_board == obj.id_status_task.id_board
                ):
                    if user_board.id_user_role.editing_task:
                        return True
                    if user_board.is_admin:
                        return True

            if 'id_block' not in request.data and 'id_status_task' not in request.data:
                if user_board.id_user_role.editing_task:
                    return True
                if user_board.is_admin:
                    return True

            if 'id_block' not in request.data:
                status_check = (
                    StatusTask.objects.select_related('id_board')
                    .filter(id=request.data.get('id_status_task'))
                    .first()
                )

                if not status_check:
                    return False

                if status_check.id_board == obj.id_status_task.id_board:
                    if user_board.id_user_role.editing_task:
                        return True
                    if user_board.is_admin:
                        return True

            if 'id_status_task' not in request.data:
                block_check = (
                    Block.objects.select_related('id_board')
                    .filter(id=request.data.get('id_block'))
                    .first()
                )
                if not block_check:
                    return False

                if block_check.id_board == obj.id_block.id_board:
                    if user_board.id_user_role.editing_task:
                        return True
                    if user_board.is_admin:
                        return True

        if request.method == 'DELETE':
            if user_board.id_user_role.deleting_task:
                return True
            if user_board.is_admin:
                return True


# UserRole
# Ограничение пользователь без разрешения на изменение создание
# и удаление ролей не может производить действия с ролями, а только просматривать
class IsUserRoleCanCRUDUserRole(permissions.BasePermission):
    def has_permission(self, request, view):

        if request.method == 'GET':
            if request.user.is_authenticated:
                return True

        if request.method == 'DELETE':
            if request.user.is_authenticated:
                return True

        if request.method == 'PATCH' or request.method == 'PUT':
            if request.user.is_authenticated:
                return True

        user_board = UserBoard.objects.select_related('id_user_role').get(
            id_board=request.data.get("id_board"), id_user=request.user.id
        )
        if not user_board:
            return False

        if request.method == "POST" and request.user.is_authenticated:
            if user_board.is_admin:
                return True
            if user_board.id_user_role.creating_role:
                return True

    def has_object_permission(self, request, view, obj):
        user = request.user

        if user.is_superuser:
            return True

        if user.is_authenticated:

            if request.method == 'GET':
                return True

            user_board = (
                UserBoard.objects.select_related("id_user_role")
                .filter(id_board=obj.id_board, id_user=user.id)
                .first()
            )

            if not user_board:
                return False

            if user_board.is_admin:
                return True

            if request.method == "DELETE":
                if user_board.id_user_role.deleting_role:
                    return True

            if 'id_board' not in request.data and request.method == 'PATCH':
                if user_board.id_user_role.editing_role:
                    return True

            if request.data.get('id_board') == user_board.id_board.id:
                if request.method == "PUT":
                    if user_board.id_user_role.editing_role:
                        return True

                if request.method == "PATCH":
                    if user_board.id_user_role.editing_role:
                        return True


# StatusTask
# Админ может делать все
# Добавление, удаление, редактирование - разрешения у роли
class IsUserRoleCanCRUDStatusTask(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            user_board = (
                UserBoard.objects.select_related('id_user_role')
                .filter(id_user=request.user.id, id_board=request.data.get('id_board'))
                .first()
            )

            if user_board:
                if user_board.is_admin:
                    return True
                if user_board.id_user_role.creating_status_task:
                    return True
                return False
            else:
                return False

        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        if not request.user.is_authenticated:
            return False

        if request.method == 'GET':
            return True

        user_board = (
            UserBoard.objects.select_related('id_user_role')
            .filter(id_user=request.user.id, id_board=obj.id_board.id)
            .first()
        )

        if user_board:
            if request.method == 'PUT':
                return False
            if user_board.is_admin:
                return True

            if request.method == 'DELETE':
                if user_board.id_user_role.deleting_status_task:
                    return True
            if request.method == 'PATCH':
                if user_board.id_user_role.editing_status_task:
                    if 'id_board' not in request.data:
                        return True


# UserBoard
# Пользователь может удалять себя
# Добавление пользователя, удаление, изменение проходит если пользователь имеет нужную роль
class IsUserOrUserRoleCanEditDelete(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True

        if request.method == 'POST':
            if request.user.is_authenticated:
                user_board_exists = view.queryset.filter(
                    id_user=request.data.get('id_user'),
                    id_board=request.data.get('id_board'),
                ).first()

                if user_board_exists:
                    return False

                # проверка есть ли у пользователя роль в этой доске и имеет ли он разрешение на добавление участников
                user_board = (
                    view.queryset.select_related('id_user_role')
                    .filter(
                        id_user=request.user.id,
                        id_board=request.data.get('id_board'),
                    )
                    .first()
                )
                if not user_board:
                    return False

                if user_board.is_admin:
                    return True

                # проверка имеет ли пользователь разрешение на добавление и одинаковые ли доски указаны в роли и в юзер борде
                if user_board.id_user_role.add_members:
                    role = UserRole.objects.get(id=request.data.get('id_user_role'))

                    if not role:
                        return False

                    if user_board.id_board == role.id_board:
                        return True
            return False

        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user == obj.id_user and obj.is_admin == True:
            return True
        if request.user.is_superuser:
            return True

        if request.user.is_authenticated:
            if request.method == permissions.SAFE_METHODS:
                return True

            user_board = (
                view.queryset.select_related('id_user_role')
                .filter(id_user=request.user.id, id_board=obj.id_board)
                .first()
            )
            if user_board:
                if request.method == 'PUT':  # не разрешен
                    return False
                if user_board.is_admin:
                    return True

                if request.method == 'PATCH':  # можно изменять только роль
                    if (
                        'id_user' not in request.data
                        and 'id_board' not in request.data
                        and 'is_admin' not in request.data
                    ):
                        # проверка на одинаковые id_board
                        if user_board.id_user_role.edit_members:
                            if user_board.id_board == obj.id_user_role.id_board:
                                return True

                if request.method == 'DELETE':
                    if user_board.id_user_role.delete_members:
                        return True
                    if request.user == obj.id_user:
                        return True
