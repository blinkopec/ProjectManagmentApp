from django.shortcuts import render
from rest_framework import generics
from .models import User, StatusTask, UserRole, UserBoard,Board,Comment,Block,Task
from .serializers import  UserSerializer, StatusTaskSerializer, UserRoleSerializer, UserBoardSerializer, BoardSerializer,CommentSerializer,BlockSerializer,TaskSerializer,ExtUserSerializer
from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from django.http import JsonResponse
from rest_framework import permissions, status
from .permissions import IsAdminOrReadOnly, IsOwnerOrReadOnly, IsUserOrReadOnly, IsUserRelateToBoardOrReadOnly, IsUserRelateToBlockOrReadOnly, IsUserRelateToTaskOrReadOnly


# User
class UserAPIView(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsUserOrReadOnly]
    
    # настройка отображения для админа и для обычных, себя юзер должен видеть в полной мере
    def retrieve(self, request, pk):
        user = request.user
        usr = self.queryset.get(id=pk)
        
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

# StatusTask
class StatusTaskAPIView(ModelViewSet):
    queryset = StatusTask.objects.all()
    serializer_class = StatusTaskSerializer
    permission_classes = [IsAdminOrReadOnly]

# UserRole
class UserRoleAPIView(ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [IsAdminOrReadOnly]

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
            
            id_board = Board.objects.latest('id').id
            data={'id_user': request.user.id, 'id_board': id_board, 'id_user_role': 1}
            userboard_serializer = UserBoardSerializer(data=data)
            if userboard_serializer.is_valid():
                userboard_serializer.save()
                return Response(board_serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(userboard_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            response.append(board_serializer.errors)
            response.append(userboard_serializer.errors)
            
            return Response(response,status=status.HTTP_400_BAD_REQUEST)
        
    
    # Выводит только те доски, в которых есть юзер
    def get_queryset(self):
        user = self.request.user
        return self.queryset.filter(id__in=UserBoard.objects.all().filter(id_user=user.id).values_list('id_board', flat=True))

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
        blocks_ids = Block.objects.filter(id_board__in=board_ids).values_list('id', flat=True)
        task_ids = Task.objects.filter(id_block__in=blocks_ids).values_list('id', flat=True)
        return self.queryset.filter(id_task__in=task_ids)

# Block
class BlockAPIView (ModelViewSet):
    queryset = Block.objects.all()
    serializer_class = BlockSerializer
    permission_classes = [IsUserRelateToBlockOrReadOnly]

    # Выводит только те блоки, которые принадлежат к доскам, в которых есть пользователь
    def get_queryset(self):
        user = self.request.user
        return self.queryset.filter(id_board__in=UserBoard.objects.all().filter(id_user=user.id).values_list('id_board', flat=True))

# Task
class TaskAPIView(ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [IsUserRelateToTaskOrReadOnly]

    # Выводит только те задачи, которые принадлежат к доскам, в которых есть пользователь
    def get_queryset(self):
        user = self.request.user
        id_board = UserBoard.objects.all().filter(id_user=user.id).values_list('id_board', flat=True)
        id_blocks = Block.objects.all().filter(id_board__in=id_board).values_list('id', flat=True)
        tasks = self.queryset.filter(id_block__in=id_blocks)
        return tasks
    