from rest_framework import permissions
from collections.abc import Iterable
from .models import UserBoard, Block, Board

class ReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS


class IsAdminOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        
        return bool(request.user and request.user.is_staff)

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

        if UserBoard.objects.all().filter(id_user=request.user, id_board=obj.id_block.id_board):
            return True
        
        if request.method in permissions.SAFE_METHODS:
            return True
