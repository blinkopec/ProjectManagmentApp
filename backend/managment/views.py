from django.shortcuts import render
from rest_framework import generics
from .models import User, StatusTask, UserRole, UserBoard, Board, Comment, Block, Task
from .serializers import (
    UserSerializer,
    StatusTaskSerializer,
    UserRoleSerializer,
    UserBoardSerializer,
    BoardSerializer,
    CommentSerializer,
    BlockSerializer,
    TaskSerializer,
    ExtUserSerializer,
    UpdateUserSerializer,
)
from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from django.http import JsonResponse
from rest_framework import permissions, status
from .permissions import (
    IsAdminOrReadOnly,
    IsOwnerOrReadOnly,
    IsUserOrReadOnly,
    IsUserRelateToBoardOrReadOnly,
    IsUserRelateToBlockOrReadOnly,
    IsUserRelateToTaskOrReadOnly,
    IsUserCanEditingTaskOrReadOnly,
)
from django.contrib.auth.hashers import make_password


# User
class UserAPIView(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsUserOrReadOnly]

    # настройка отображения для админа и для обычных, себя юзер должен видеть в полной мере
    def retrieve(self, request, pk):
        user = request.user
        usr = self.queryset.get(id=pk)

        #! if необычный
        if user.id == usr.id:
            serializer = UserSerializer(usr)
            return Response(serializer.data)

        if user.is_superuser:
            serializer = UserSerializer(usr)
            return Response(serializer.data)

        serializer = ExtUserSerializer(usr)
        return Response(serializer.data)

    def list(self, request):
        serializer = ExtUserSerializer(self.queryset, many=True)
        return Response(serializer.data)

    def partial_update(self, request, pk=None):
        user = request.user
        usr = self.queryset.get(id=pk)
        if user.id != usr.id and user.is_superuser == False:
            return Response("access denied", status=status.HTTP_403_FORBIDDEN)

        if user.is_superuser:
            serializer = UserSerializer(usr, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer = UpdateUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # чтобы пользователь не мог сделать себя админом
    def update(self, request, pk=None):
        user = request.user
        usr = self.queryset.get(id=pk)
        if user.id != usr.id and user.is_superuser == False:
            return Response("access denied", status=status.HTTP_403_FORBIDDEN)

        if user.is_superuser:
            serializer = UserSerializer(usr, data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer = UpdateUserSerializer(user, data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)

        if request.user.is_superuser == False:
            return Response(status=status.HTTP_403_FORBIDDEN)

        if serializer.is_valid():
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(
                serializer.data, status=status.HTTP_201_CREATED, headers=headers
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# StatusTask
class StatusTaskAPIView(ModelViewSet):
    queryset = StatusTask.objects.all()
    serializer_class = StatusTaskSerializer
    permission_classes = [IsAdminOrReadOnly]


# UserRole
class UserRoleAPIView(ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [IsUserCanEditingTaskOrReadOnly]

    # Изменять может только пользователь с нужным разрешением или суперпользователь
    # def partial_update(self, request, pk=None):
    #     user = request.user
    #     user_role = self.queryset.get(id=pk)
    #
    #     if user.is_superuser:
    #         serializer = UserRoleSerializer(user_role, data=request.data, partial=True)
    #         if serializer.is_valid(raise_exception=True):
    #             serializer.save()
    #             return Response(serializer.data, status=status.HTTP_200_OK)
    #         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    #
    #     user_board_role = UserBoard.objects.get(id_user_role=pk)
    #
    #     if user == user_board_role.id_user:
    #         if user_board_role.id_user_role.editing_role:
    #             serializer = UserRoleSerializer(
    #                 user_role, data=request.data, partial=True
    #             )
    #             if serializer.is_valid(raise_exception=True):
    #                 serializer.save()
    #                 return Response(serializer.data, status=status.HTTP_200_OK)
    #             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    #         else:
    #             return Response("access denied", status=status.HTTP_403_FORBIDDEN)
    #
    #     user_board = UserBoard.objects.get(
    #         id_board=user_board_role.id_board, id_user=user.id
    #     )
    #
    #     if user_board != None:
    #         if user_board.id_user_role.editing_role:
    #             serializer = UserRoleSerializer(
    #                 user_role, data=request.data, partial=True
    #             )
    #             if serializer.is_valid(raise_exception=True):
    #                 serializer.save()
    #                 return Response(serializer.data, status=status.HTTP_200_OK)
    #             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    #         else:
    #             return Response("access denied", status=status.HTTP_403_FORBIDDEN)
    #     else:
    #         return Response("acces denied", status=status.HTTP_403_FORBIDDEN)
    #
    # Изменять может только пользователь с нужным разрешением или суперпользователь
    def update(self, request, pk=None):
        user = request.user
        user_role = self.queryset.get(id=pk)

        if user.is_superuser:
            serializer = UserRoleSerializer(user_role, data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user_board_role = UserBoard.objects.get(id_user_role=pk)

        if user == user_board_role.id_user:
            if user_board_role.id_user_role.editing_role:
                serializer = UserRoleSerializer(user_role, data=request.data)
                if serializer.is_valid(raise_exception=True):
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response("access denied", status=status.HTTP_403_FORBIDDEN)

        user_board = UserBoard.objects.get(
            id_board=user_board_role.id_board, id_user=user.id
        )

        if user_board != None:
            if user_board.id_user_role.editing_role:
                serializer = UserRoleSerializer(user_role, data=request.data)
                if serializer.is_valid(raise_exception=True):
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response("access denied", status=status.HTTP_403_FORBIDDEN)
        else:
            return Response("acces denied", status=status.HTTP_403_FORBIDDEN)

    # Удалять может только пользователь с нужным разрешением или суперпользователь
    def destroy(self, request, pk=None):
        #! проверка доски что у пользователя есть разрешение на удаление
        pass


# UserBoard
class UserBoardAPIView(ModelViewSet):
    queryset = UserBoard.objects.all()
    serializer_class = UserBoardSerializer
    permission_classes = [IsOwnerOrReadOnly]


# Board
class BoardAPIView(ModelViewSet):
    queryset = Board.objects.all()
    serializer_class = BoardSerializer
    permission_classes = [IsUserRelateToBoardOrReadOnly]

    # При создании доски приписывает юзера к доске как владельца
    def create(self, request):
        board_serializer = BoardSerializer(data=request.data)
        if board_serializer.is_valid():
            board_serializer.save()

            id_board = Board.objects.latest("id").id
            data = {"id_user": request.user.id, "id_board": id_board, "id_user_role": 1}
            userboard_serializer = UserBoardSerializer(data=data)
            if userboard_serializer.is_valid():
                userboard_serializer.save()
                return Response(board_serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(
                    userboard_serializer.errors, status=status.HTTP_400_BAD_REQUEST
                )
        else:
            response.append(board_serializer.errors)
            response.append(userboard_serializer.errors)

            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    # Выводит только те доски, в которых есть юзер
    def get_queryset(self):
        user = self.request.user
        return self.queryset.filter(
            id__in=UserBoard.objects.all()
            .filter(id_user=user.id)
            .values_list("id_board", flat=True)
        )


# Comment
class CommentAPIView(ModelViewSet):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsOwnerOrReadOnly]

    # Чтобы выводило только те комменты, которые относятся к таскам,
    # которые принадлежат доскам, в которых есть пользователь
    def get_queryset(self):
        user = self.request.user
        user_boards = UserBoard.objects.filter(id_user=user.id)
        board_ids = [board.id_board for board in user_boards]
        blocks_ids = Block.objects.filter(id_board__in=board_ids).values_list(
            "id", flat=True
        )
        task_ids = Task.objects.filter(id_block__in=blocks_ids).values_list(
            "id", flat=True
        )
        return self.queryset.filter(id_task__in=task_ids)


# Block
class BlockAPIView(ModelViewSet):
    queryset = Block.objects.all()
    serializer_class = BlockSerializer
    permission_classes = [IsUserRelateToBlockOrReadOnly]

    # Выводит только те блоки, которые принадлежат к доскам, в которых есть пользователь
    def get_queryset(self):
        user = self.request.user
        return self.queryset.filter(
            id_board__in=UserBoard.objects.all()
            .filter(id_user=user.id)
            .values_list("id_board", flat=True)
        )


# Task
class TaskAPIView(ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [IsUserRelateToTaskOrReadOnly]

    # Выводит только те задачи, которые принадлежат к доскам, в которых есть пользователь
    def get_queryset(self):
        user = self.request.user
        id_board = (
            UserBoard.objects.all()
            .filter(id_user=user.id)
            .values_list("id_board", flat=True)
        )
        id_blocks = (
            Block.objects.all()
            .filter(id_board__in=id_board)
            .values_list("id", flat=True)
        )
        tasks = self.queryset.filter(id_block__in=id_blocks)
        return tasks
