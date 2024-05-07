from http.client import INSUFFICIENT_STORAGE
from django.db.models.query import FlatValuesListIterable
from rest_framework import permissions
from collections.abc import Iterable
from .models import UserBoard, Block, Board, UserRole


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


# Ограничение пользователь без разрешения на изменение создание
# и удаление ролей не может производить действия с ролями, а только просматривать
class IsUserCanEditingTaskOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        user = request.user

        if user.is_superuser:
            return True

        # roles = UserRole.objects.filter(
        # id__in=UserBoard.objects.all()
        # .filter(id_user=user.id)
        # .values_list("id_user_role", flat=True)
        # )

        # for role in roles:
        # if role.creating_role:
        # return True

        # if role.editing_role:
        # return True

        # if role.deleting_role:
        # return True

        user_board = (
            UserBoard.objects.get(
                id_board=request.data.get("id_board"), id_user=user.id
            )
            .select_related("user_role")
            .first()
        )

        # Обработчик на create
        if request.method == "POST":
            if user_board.id_user_role.creating_role:
                return True

        if request.method == "PUT":
            if user_board.id_user_role.editing_role:
                return True

        if request.method == "PATCH":
            if user_board.id_user_role.editing_role:
                return True

        if request.method == "DELETE":
            if user_board.id_user_role.deleting_role:
                return True
