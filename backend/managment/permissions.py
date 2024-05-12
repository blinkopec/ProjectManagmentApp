from collections.abc import Iterable
from http.client import INSUFFICIENT_STORAGE
from typing import TypeGuard, reveal_type

from django.db.models.fields.related import resolve_relation
from django.db.models.functions import TruncYear
from django.db.models.query import FlatValuesListIterable
from django.middleware.csrf import is_same_domain
from django.utils.encoding import repercent_broken_unicode
from rest_framework import permissions

from .models import Block, Board, UserBoard, UserRole


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

        if UserBoard.objects.all().filter(id_user=request.user, id_board=obj.id):
            return True

        if request.method in permissions.SAFE_METHODS:
            return True


class IsUserRelateToBlockOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        if UserBoard.objects.all().filter(id_user=request.user, id_board=obj.id_board):
            return True

        if request.method in permissions.SAFE_METHODS:
            return True


class IsUserRelateToTaskOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        if UserBoard.objects.all().filter(
            id_user=request.user, id_board=obj.id_block.id_board
        ):
            return True

        if request.method in permissions.SAFE_METHODS:
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

            user_board = UserBoard.objects.select_related("id_user_role").get(
                id_board=obj.id_board, id_user=user.id
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
            if request.method == 'GET':
                return True

            if request.method == 'PATCH':  # можно изменять только роль
                if 'id_user' not in request.data and 'id_board' not in request.data:
                    user_board = (
                        view.queryset.select_related('id_user_role')
                        .filter(id_user=request.user.id, id_board=obj.id_board)
                        .first()
                    )
                    if not user_board:
                        return False

                    # проверка на одинаковые id_board
                    if user_board.id_user_role.edit_members:
                        if user_board.id_board == obj.id_user_role.id_board:
                            return True

            if request.method == 'PUT':  # не разрешен
                return False

            if request.method == 'DELETE':
                if request.user == obj.id_user:
                    return True
                user_board = (
                    view.queryset.select_related('id_user_role')
                    .filter(id_user=request.user.id, id_board=obj.id_board)
                    .first()
                )

                if not user_board:
                    return False

                if user_board.id_user_role.delete_members:
                    return True
