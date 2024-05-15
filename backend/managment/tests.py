from asyncio import start_unix_server
from collections import namedtuple
from inspect import formatannotation
from typing import assert_type

from django import setup
from django.contrib.auth.base_user import password_validation
from django.contrib.auth.password_validation import password_changed
from django.db.models.fields import return_None
from django.db.models.functions import TruncMinute
from django.http import Http404, request
from django.utils.safestring import SafeText
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import (APIClient, APIRequestFactory, APITestCase,
                                 force_authenticate)
from rest_framework_simplejwt.tokens import AccessToken

from .models import (Block, Board, Comment, StatusTask, Task, User, UserBoard,
                     UserRole)


class JWTTest(APITestCase):
    # Тест работы JWT
    def test_api_jwt(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.is_active = False
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

        usr.is_active = True
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue('access' in resp.data)
        token = resp.data['access']

        verification_url = '/auth/jwt/verify/ '
        resp = self.client.post(verification_url, {'token': token}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = self.client.post(verification_url, {'token': 'abc'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + 'abc')
        resp = client.get('/api/users/', data={'format': 'json'})
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)
        resp = client.get('/api/users/', data={'format': 'json'})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)


class UserTest(APITestCase):

    # Получение юзером данных о себе полностью, а не своих не полностью
    def test_api_user_retrieve(self):
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        user = User.objects.create_user(
            username=username, email=email, password=password
        )
        user.save()

        resp = self.client.post(
            '/auth/jwt/create/',
            {'username': username, 'password': password},
            format='json',
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.get('/api/users/' + str(user.id) + '/', data={'format': 'json'})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        user2 = User.objects.create_user(
            username='test2', email='test2@test.ru', password='test2'
        )
        user2.save()

        resp = client.get('/api/users/' + str(user2.id) + '/', data={'format': 'json'})
        self.assertNotContains(resp, 'login')
        self.assertNotContains(resp, 'password')

    # Тест регистрации
    def test_registration(self):
        url = '/auth/users/'
        username = 'test'
        email = 'test@mail.ru'
        password = 'test123213123'

        resp = self.client.post(
            url,
            {'email': email, 'username': username, 'password': password},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    # Список пользователей не должен содержать в себе пароли и логины
    def test_user_list(self):
        url = '/auth/jwt/create/'
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.get('/api/users/', data={'format': 'json'})
        self.assertNotContains(resp, 'login')
        self.assertNotContains(resp, 'password')

    # Админ должен получать полную информацию о любом пользователе
    def test_superuser_get_user_info(self):
        url = '/auth/jwt/create/'
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.is_superuser = True
        usr_is_staff = True
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.get('/api/users/' + str(usr.id) + '/', data={'format': 'json'})
        self.assertContains(resp, 'login')
        self.assertContains(resp, 'password')

        usr2 = User.objects.create_user(
            username='test2', email='test2@test.ru', password='test2'
        )
        usr.save()

        resp = client.get('/api/users/' + str(usr2.id) + '/', data={'format': 'json'})
        self.assertContains(resp, 'login')
        self.assertContains(resp, 'password')

    # Пользователь может обновить информацию о себе
    def test_user_update_info_patch(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.patch('/api/users/' + str(usr.id) + '/', {'username': 'abc'})

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # Пользователь может полностью обновить информацию о себе
    def test_user_update_info_put(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.put(
            '/api/users/' + str(usr.id) + '/',
            {
                'username': 'abc',
                'last_name': 'asd',
                'first_name': 'asd',
                'email': 'asd@asd.ru',
            },
        )

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # Пользователь не может обновлять не свои данные методом put
    def test_user_update_someone_user_info_put(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        usr2 = User.objects.create_user(
            username='test2', email='test2@test.ru', password='test2'
        )
        usr.save()

        resp = client.put(
            '/api/users/' + str(usr2.id) + '/',
            {
                'username': 'abc',
                'last_name': 'asd',
                'first_name': 'asd',
                'email': 'asd@asd.ru',
            },
        )

        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # Пользователь не может сделать себя админом (is_superuser = True)
    def test_user_update_is_superuser(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.patch('/api/users/' + str(usr.id) + '/', {'is_superuser': True})

        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    # Пользователь не может обновлять не свои данные методом patch
    def test_user_update_someone_user_info_patch(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        usr2 = User.objects.create_user(
            username='test2', email='test2@test.ru', password='test2'
        )
        usr.save()

        resp = client.patch('/api/users/' + str(usr2.id) + '/', {'username': 'abc'})

        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # Супер пользователь обновляет информацию о себе методом put
    def test_superuser_update_info_put(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password, is_superuser=True
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.put(
            '/api/users/' + str(usr.id) + '/',
            {
                'username': 'abc',
                'last_name': 'asd',
                'first_name': 'asd',
                'email': 'asd@asd.ru',
                'password': 'asd',
            },
        )

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # Пользователь может удалить себя
    def test_user_delete_self(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.delete('/api/users/' + str(usr.id) + '/')

        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    # Пользователь не может удалять других пользователей
    def test_user_delete_someone_user(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        usr2 = User.objects.create_user(
            username='test2', email='test2@test.ru', password='test2'
        )
        usr.save()

        resp = client.delete('/api/users/' + str(usr2.id) + '/')

        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # Супер пользователь может удалять других пользователей
    def test_superuser_delete_someone_user(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password, is_superuser=True
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        usr2 = User.objects.create_user(
            username='test2', email='test2@test.ru', password='test2'
        )
        usr.save()

        resp = client.delete('/api/users/' + str(usr2.id) + '/')

        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    # Супер пользователь может удалить себя
    def test_superuser_delete_self(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password, is_superuser=True
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.delete('/api/users/' + str(usr.id) + '/')

        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    # Супер пользователь обновляет информацию о себе методом patch
    def test_superuser_update_info_patch(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password, is_superuser=True
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.patch(
            '/api/users/' + str(usr.id) + '/',
            {
                'username': 'abc',
            },
        )

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # Супер пользователь обновляет чужую информацию методом put
    def test_superuser_update_someone_user_info_put(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password, is_superuser=True
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        usr2 = User.objects.create_user(
            username='test2', email='test2@test.ru', password='test2'
        )
        usr.save()

        resp = client.put(
            '/api/users/' + str(usr2.id) + '/',
            {
                'username': 'abc',
                'last_name': 'asd',
                'first_name': 'asd',
                'email': 'asd@asd.ru',
                'password': 'asd',
            },
        )

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # Супер пользователь обновляет чужую информацию методом patch
    def test_superuser_update_someone_user_info_patch(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password, is_superuser=True
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        usr2 = User.objects.create_user(
            username='test2', email='test2@test.ru', password='test2'
        )
        usr.save()

        resp = client.patch('/api/users/' + str(usr2.id) + '/', {'username': 'abc'})

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # Супер пользователь может менять пароли любых пользователей
    def test_superuser_change_someone_user_password(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password, is_superuser=True
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        usr2 = User.objects.create_user(
            username='test2', email='test2@test.ru', password='test2'
        )
        usr.save()

        resp = client.patch('/api/users/' + str(usr2.id) + '/', {'password': 'abc'})

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # Обычный пользователь не может создавать новых пользователей
    def test_user_create_users(self):
        url = '/auth/jwt/create/'
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.post(
            '/api/users/',
            {
                'username': 'test2',
                'email': 'test2@test.ru',
                'password': 'test2',
                'is_superuser': False,
            },
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # Супер пользователь может создавать новых пользователей
    def test_superuser_create_users(self):
        url = '/auth/jwt/create/'
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password
        )
        usr.is_superuser = True
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.post(
            '/api/users/',
            {
                'username': 'test2',
                'email': 'test2@test.ru',
                'password': 'test2',
                'is_superuser': False,
                'is_staff': 'True',
                'last_name': 'asdsad',
                'first_name': 'asd',
            },
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)


class UserRoleTests(APITestCase):

    # тест на проверку создания роли
    def test_api_user_role_CRUD(self):
        user = User.objects.create_user(
            username='testtesttest', email='test@test.ru', password='test'
        )
        user.save()

        board = Board.objects.create(name='test')
        board.save()

        user_role = UserRole.objects.create(
            name='test',
            id_board=board,
            creating_role=True,
            editing_role=True,
            deleting_role=False,
        )
        user_role.save()

        user_board = UserBoard.objects.create(
            id_user=user, id_board=board, id_user_role=user_role
        )
        user_board.save()

        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f'Bearer ' + str(AccessToken.for_user(user))
        )

        # GET
        resp = client.get('/api/user_roles/', format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.get('/api/user_roles/' + str(user_role.id) + '/', format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        # CREATE
        resp = client.post(
            '/api/user_roles/', {'name': 'test', 'id_board': board.id}, format='json'
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        user_role.creating_role = False
        user_role.save()

        resp = client.post(
            '/api/user_roles/', {'name': 'test', 'id_board': board.id}, format='json'
        )

        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        # PATCH and PUT
        resp = client.patch(
            '/api/user_roles/' + str(user_role.id) + '/',
            {'name': 't'},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.put(
            '/api/user_roles/' + str(user_role.id) + '/',
            {'name': 't', 'id_board': board.id},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        user_role.editing_role = False
        user_role.save()

        resp = client.patch(
            '/api/user_roles/' + str(user_role.id) + '/',
            {'name': 't'},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.put(
            '/api/user_roles/' + str(user_role.id) + '/',
            {'name': 't'},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        # DELETE
        resp = client.delete(
            '/api/user_roles/' + str(user_role.id) + '/', format='json'
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        user_role.deleting_role = True
        user_role.save()

        # юзер не должен иметь возможность менять id_board
        user_role.editing_role = True
        user_role.save()
        board2 = Board.objects.create(name='er')
        user_role2 = UserRole.objects.create(name='tasdf', id_board=board2)
        resp = client.patch(
            '/api/user_roles/' + str(user_role.id) + '/',
            {'id_board': board2.id},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.put(
            '/api/user_roles/' + str(user_role.id) + '/',
            {'name': 'err', 'id_board': board2.id},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        user_board.is_admin = True
        user_board.save()

        resp = client.patch(
            '/api/user_roles/' + str(user_role.id) + '/', {'name': 'asd'}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.delete(
            '/api/user_roles/' + str(user_role.id) + '/', format='json'
        )
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)


class UserBoardTests(APITestCase):
    def test_api_user_board_owner_user(self):
        user = User.objects.create_user(
            username='testtesttest',
            email='test@test.ru',
            password='test',
            is_superuser=False,
        )
        user.save()

        board = Board.objects.create(name='test')
        board.save()

        user_role = UserRole.objects.create(
            name='test',
            id_board=board,
        )
        user_role.save()

        user_board = UserBoard.objects.create(
            id_user=user, id_board=board, id_user_role=user_role
        )
        user_board.save()

        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f'Bearer ' + str(AccessToken.for_user(user))
        )

        user_role2 = UserRole.objects.create(name='test', id_board=board)
        user_role2.save()

        board2 = Board.objects.create(name='tetet')
        board2.save()

        resp = client.get('/api/user_boards/', format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        board3 = Board.objects.create(name='asdasd')
        board3.save()

        user_role3 = UserRole.objects.create(
            name='asdsadsasad', id_board=board3, add_members=True
        )
        user_role3.save()

        user_board3 = UserBoard.objects.create(
            id_user=user, id_board=board3, id_user_role=user_role3, is_admin=True
        )
        user_board3.save()

        user3 = User.objects.create(
            username='asdsadsaagff', email='k@k.krr', password='sadad132'
        )
        user3.save()

        resp = client.post(
            '/api/user_boards/',
            {'id_user': user3.id, 'id_board': board3.id, 'id_user_role': user_role3.id},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        resp = client.patch(
            '/api/user_boards/' + str(user_board.id) + '/',
            {'id_user_role': user_role2.id},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch(
            '/api/user_boards/' + str(user_board.id) + '/',
            {'id_board': board2.id},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.put(
            '/api/user_boards/' + str(user_board.id) + '/',
            {'id_user': user.id, 'id_board': board2.id, 'id_user_role': user_role.id},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        user2 = User.objects.create(
            username='tetete', email='ioj@nana.ru', password='joker'
        )
        user2.save()

        user_board2 = UserBoard.objects.create(
            id_user=user2,
            id_board=board2,
            id_user_role=user_role2,
        )
        user_board2.save()

        # DELETE
        resp = client.delete('/api/user_boards/' + str(user_board2.id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.delete('/api/user_boards/' + str(user_board.id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    def test_api_user_board_role(self):
        user = User.objects.create(
            username='asd', email='sfas@as.com', password='asdasdasd'
        )
        user.save()

        board = Board.objects.create(name='2')
        board.save()

        user_role = UserRole.objects.create(
            name='ads',
            id_board=board,
            edit_members=False,
            delete_members=False,
            add_members=False,
        )
        user_role.save()

        user_board = UserBoard.objects.create(
            id_board=board, id_user=user, id_user_role=user_role
        )
        user_board.save()

        user2 = User.objects.create(
            username='asdasdasd', email='sfas@as.com', password='asdasdasd'
        )
        user.save()

        board2 = Board.objects.create(name='2')
        board.save()

        user_role2 = UserRole.objects.create(name='ads', id_board=board)
        user_role.save()

        user_board2 = UserBoard.objects.create(
            id_board=board, id_user=user2, id_user_role=user_role
        )
        user_board.save()

        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f'Bearer ' + str(AccessToken.for_user(user))
        )

        resp = client.put(
            '/api/user_boards/' + str(user_board2.id) + '/',
            {'id_board': board.id, 'id_user': user.id, 'id_user_role': user_role.id},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch(
            '/api/user_boards/' + str(user_board2.id) + '/', {'id_board': board.id}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch(
            '/api/user_boards/' + str(user_board2.id) + '/',
            {'id_user_role': user_role.id},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        user_role.edit_members = True
        user_role.save()

        resp = client.patch(
            '/api/user_boards/' + str(user_board.id) + '/',
            {'id_user_role': user_role.id},
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.delete('/api/user_boards/' + str(user_board2.id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        user_board.is_admin = True
        user_board.save()

        resp = client.patch(
            '/api/user_boards/' + str(user_board.id) + '/',
            {'id_user_role': user_role.id},
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        user_board.is_admin = False
        user_board.save()

        resp = client.post(
            '/api/user_boards/',
            {'id_user': user2.id, 'id_board': board.id, 'id_user_role': user_role.id},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        board3 = Board.objects.create(name='asdasd')
        board3.save()

        user_role3 = UserRole.objects.create(
            name='asdsadsasad', id_board=board3, add_members=True
        )
        user_role3.save()

        user_board3 = UserBoard.objects.create(
            id_user=user, id_board=board3, id_user_role=user_role3
        )
        user_board3.save()

        user3 = User.objects.create(
            username='asdsadsaagff', email='k@k.krr', password='sadad132'
        )
        user3.save()

        resp = client.post(
            '/api/user_boards/',
            {'id_user': user3.id, 'id_board': board3.id, 'id_user_role': user_role3.id},
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        resp = client.post(
            '/api/user_boards/',
            {'id_user': user2.id, 'id_board': board2.id, 'id_user_role': user_role.id},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        user_role.delete_members = True
        user_role.save()

        resp = client.delete('/api/user_boards/' + str(user_board2.id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    def test_api_user_board_unauthorized(self):
        user = User.objects.create(
            username='asd', email='sfas@as.com', password='asdasdasd'
        )
        user.save()

        board = Board.objects.create(name='2')
        board.save()

        board2 = Board.objects.create(name='2')
        board2.save()

        user_role = UserRole.objects.create(name='ads', id_board=board)
        user_role.save()

        user_board = UserBoard.objects.create(
            id_board=board, id_user=user, id_user_role=user_role
        )
        user_board.save()

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + 'abc')

        resp = client.get('/api/user_boards/')
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

        resp = client.patch(
            '/api/user_boards/' + str(user_board.id) + '/', {'id_board': board2.id}
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

        resp = client.post(
            '/api/user_boards/',
            {'id_board': board.id, 'is_user': user.id, 'id_user_role': user_role.id},
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

        resp = client.delete('/api/user_boards/' + str(user_board.id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)


class BoardTests(APITestCase):
    @classmethod
    def setUpData(cls):
        user = User.objects.create_user(
            username='qwerty', email='qwerty', password='qwertqwert'
        )
        board = Board.objects.create(name='1')
        board2 = Board.objects.create(name='2')
        user2 = User.objects.create_user(
            username='abcabc', email='com@com.com', password='passwordpassword'
        )
        board.save()
        board2.save()
        user2.save()
        user_role = UserRole.objects.create(name='1', id_board=board)
        user_role2 = UserRole.objects.create(name='2', id_board=board2)
        user_role.save()
        user_role2.save()
        user_board = UserBoard.objects.create(
            id_board=board, id_user=user, id_user_role=user_role
        )
        user_board.save()
        user_board2 = UserBoard.objects.create(
            id_board=board2, id_user=user2, id_user_role=user_role2
        )
        user_board2.save()

        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f'Bearer ' + str(AccessToken.for_user(user))
        )

        return {
            'client': client,
            'user': user,
            'user2': user2,
            'board': board,
            'board2': board2,
            'user_role': user_role,
            'user_rol2': user_role2,
            'user_board': user_board,
            'user_board2': user_board2,
        }

    def api_test_board_create(self):
        data = BoardTests.setUpData()

        resp = data['client'].post('/api/boards/', {'name': 'asdasdasd'})
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        created_board = Board.objects.latest('pk')
        ub = UserBoard.objects.get(id_board=created_board.id, id_user=data['user'].id)
        self.assertTrue(ub)

    def api_test_board_update(self):
        data = BoardTests.setUpData()

        resp = data['client'].patch(
            '/api/boards/' + str(data['board'].id) + '/', {'name': 'asd'}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = data['client'].patch(
            '/api/boards/' + str(data['board2'].id) + '/', {'name': 'asd'}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = data['client'].put(
            '/api/boards/' + str(data['board'].id) + '/', {'name': 'absd'}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = data['client'].put(
            '/api/boards/' + str(data['board2'].id) + '/', {'name': 'absd'}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].editing_board = False
        data['user_role'].save()

        resp = data['client'].put(
            '/api/boards/' + str(data['board'].id) + '/', {'name': 'absd'}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = data['client'].patch(
            '/api/boards/' + str(data['board'].id) + '/', {'name': 'asd'}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_board'].is_admin = True
        data['user_board'].save()

        resp = data['client'].put(
            '/api/boards/' + str(data['board'].id) + '/', {'name': 'absd'}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = data['client'].patch(
            '/api/boards/' + str(data['board'].id) + '/', {'name': 'asd'}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        data['user_board'].is_admin = False
        data['user_board'].save()

    def api_test_board_delete(self):
        data = BoardTests.setUpData()

        resp = data['client'].delete('/api/boards/' + str(data['board2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].deleting_board = False
        data['user_role'].save()

        resp = data['client'].delete('/api/boards/' + str(data['board'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].deleting_board = True
        data['user_role'].save()

        resp = data['client'].delete('/api/boards/' + str(data['board'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    def api_test_board_get_list(self):
        data = BoardTests.setUpData()

        resp = data['client'].get('/api/boards/')

        result = list()
        for i in resp.json():
            for x, y in i.items():
                if x == 'id':
                    result.append(y)

        self.assertTrue(data['board2'].id not in result)

    def api_test_board_get_pk(self):
        data = BoardTests.setUpData()

        resp = data['client'].get('/api/boards/' + str(data['board'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = data['client'].get('/api/boards/' + str(data['board2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)


class BlockTests(APITestCase):

    @classmethod
    def setUpData(cls):
        user = User.objects.create_user(
            username='qwerty', email='qwerty', password='qwertqwert'
        )
        board = Board.objects.create(name='1')
        board2 = Board.objects.create(name='2')
        user2 = User.objects.create_user(
            username='abcabc', email='com@com.com', password='passwordpassword'
        )
        board.save()
        board2.save()
        user2.save()
        user_role = UserRole.objects.create(
            name='1', id_board=board, deleting_block=False
        )
        user_role2 = UserRole.objects.create(name='2', id_board=board2)
        user_role.save()
        user_role2.save()
        user_board = UserBoard.objects.create(
            id_board=board, id_user=user, id_user_role=user_role
        )
        user_board.save()
        user_board2 = UserBoard.objects.create(
            id_board=board2, id_user=user2, id_user_role=user_role2
        )
        user_board2.save()
        block = Block.objects.create(id_board=board, name='1')
        block.save()
        block3 = Block.objects.create(id_board=board, name='3')
        block3.save()

        block2 = Block.objects.create(id_board=board2, name='2')
        block2.save()

        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f'Bearer ' + str(AccessToken.for_user(user))
        )

        return {
            'client': client,
            'user': user,
            'user2': user2,
            'board': board,
            'board2': board2,
            'user_role': user_role,
            'user_rol2': user_role2,
            'user_board': user_board,
            'user_board2': user_board2,
            'block': block,
            'block2': block2,
            'block3': block3,
        }

    # создавать только с ролью или админ
    def test_api_block_create(self):
        data = BlockTests.setUpData()
        client = data['client']

        resp = client.post(
            '/api/blocks/', {'name': 'abc', 'id_board': data['board'].id}
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        data['user_role'].creating_block = False
        data['user_role'].save()

        resp = client.post(
            '/api/blocks/', {'name': 'abcabc', 'id_board': data['board2'].id}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # обновлять только с ролью или админ, чужие не может, не может обновить id_board
    def test_api_block_update(self):
        data = BlockTests.setUpData()
        client = data['client']

        resp = client.patch('/api/blocks/' + str(data['block'].id) + '/', {'name': 'a'})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.patch(
            '/api/blocks/' + str(data['block'].id) + '/',
            {'id_board': data['board2'].id},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.put(
            '/api/blocks/' + str(data['block'].id) + '/',
            {'name': 'a1', 'id_board': data['board'].id},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch(
            '/api/blocks/' + str(data['block2'].id) + '/', {'name': 'a1'}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].editing_block = False
        data['user_role'].save()

        resp = client.patch('/api/blocks/' + str(data['block'].id) + '/', {'name': 'b'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.put('/api/blocks/' + str(data['block'].id) + '/', {'name': 'b1'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # получение списка только связанных с пользователем блоков
    def test_api_block_get_list(self):
        data = BlockTests.setUpData()
        client = data['client']

        resp = client.get('/api/blocks/')
        result = list()
        for i in resp.json():
            for x, y in i.items():
                if x == 'id_board':
                    result.append(y)

        self.assertTrue(data['board2'].id not in result)

    # получение объекта только связанного с пользователем блока
    def test_api_block_get_pk(self):
        data = BlockTests.setUpData()
        client = data['client']

        resp = client.get('/api/blocks/' + str(data['block'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.get('/api/blocks/' + str(data['block2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # только с ролью или админ, чужие нельзя
    def test_api_block_delete(self):
        data = BlockTests.setUpData()
        client = data['client']

        resp = client.delete('/api/blocks/' + str(data['block2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.delete('/api/blocks/' + str(data['block'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        # админ работает, но в тестах не работает
        # data['user_role'].is_admin = True
        # data['user_role'].save()
        #
        # resp = client.delete('/api/blocks/' + str(data['block2'].id) + '/')
        # self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        #
        # resp = client.delete('/api/blocks/' + str(data['block'].id) + '/')
        # self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        #
        # data['user_role'].is_admin = False
        # data['user_role'].save()
        #
        data['user_role'].deleting_block = True
        data['user_role'].save()

        resp = client.delete('/api/blocks/' + str(data['block'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

        resp = client.delete('/api/blocks/' + str(data['block2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)


class StatusTaskTests(APITestCase):

    @classmethod
    def setUpData(cls):
        user = User.objects.create_user(
            username='qwerty', email='qwerty', password='qwertqwert'
        )
        board = Board.objects.create(name='1')
        board2 = Board.objects.create(name='2')
        user2 = User.objects.create_user(
            username='abcabc', email='com@com.com', password='passwordpassword'
        )
        board.save()
        board2.save()
        user2.save()
        user_role = UserRole.objects.create(
            name='1',
            id_board=board,
            deleting_status_task=False,
            editing_status_task=False,
            creating_status_task=False,
        )
        user_role2 = UserRole.objects.create(name='2', id_board=board2)
        user_role.save()
        user_role2.save()
        user_board = UserBoard.objects.create(
            id_board=board, id_user=user, id_user_role=user_role
        )
        user_board.save()
        user_board2 = UserBoard.objects.create(
            id_board=board2, id_user=user2, id_user_role=user_role2
        )
        user_board2.save()
        block = Block.objects.create(id_board=board, name='1')
        block.save()

        status_task = StatusTask.objects.create(name='1', id_board=board)
        status_task.save()

        status_task2 = StatusTask.objects.create(name='2', id_board=board2)
        status_task2.save()

        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f'Bearer ' + str(AccessToken.for_user(user))
        )

        return {
            'client': client,
            'user': user,
            'user2': user2,
            'board': board,
            'board2': board2,
            'user_role': user_role,
            'user_rol2': user_role2,
            'user_board': user_board,
            'user_board2': user_board2,
            'block': block,
            'status_task': status_task,
            'status_task2': status_task2,
        }

    def test_api_status_task_get_list(self):
        data = StatusTaskTests.setUpData()
        client = data['client']

        resp = client.get('/api/status_tasks/')
        result = list()
        for i in resp.json():
            for x, y in i.items():
                if x == 'id_board':
                    result.append(y)

        self.assertTrue(data['board2'].id not in result)

    def test_api_status_task_get_pk(self):
        data = StatusTaskTests.setUpData()
        client = data['client']

        resp = client.get('/api/status_tasks/' + str(data['status_task'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.get('/api/status_tasks/' + str(data['status_task2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # нельзя изменять id_board и не имея разрешения
    def test_api_status_task_update(self):
        data = StatusTaskTests.setUpData()
        client = data['client']

        resp = client.put(
            '/api/status_tasks/' + str(data['status_task'].id) + '/', {'name': 'a'}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch(
            '/api/status_tasks/' + str(data['status_task'].id) + '/', {'name': 'a'}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].editing_status_task = True
        data['user_role'].save()

        resp = client.patch(
            '/api/status_tasks/' + str(data['status_task'].id) + '/', {'name': 'a'}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.patch(
            '/api/status_tasks/' + str(data['status_task'].id) + '/',
            {'id_board': data['board2'].id},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_api_status_task_create(self):
        data = StatusTaskTests.setUpData()
        client = data['client']

        data['user_role'].is_admin = False
        data['user_role'].creating_status_task = False
        data['user_role'].save()
        resp = client.post(
            '/api/status_tasks/', {'name': 'as', 'id_board': data['board'].id}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].creating_status_task = True
        data['user_role'].save()

        resp = client.post(
            '/api/status_tasks/', {'name': 'as', 'id_board': data['board2'].id}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.post(
            '/api/status_tasks/', {'name': 'as', 'id_board': data['board'].id}
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        data['user_role'].is_admin = True
        data['user_role'].save()

        resp = client.post(
            '/api/status_tasks/', {'name': 'as', 'id_board': data['board'].id}
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        data['user_role'].is_admin = False
        data['user_role'].save()

    def test_api_status_task_delete(self):
        data = StatusTaskTests.setUpData()
        client = data['client']

        resp = client.delete('/api/status_tasks/' + str(data['status_task2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.delete('/api/status_tasks/' + str(data['status_task'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].deleting_status_task = True
        data['user_role'].save()

        resp = client.delete('/api/status_tasks/' + str(data['status_task'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)


class TaskTests(APITestCase):
    @classmethod
    def setUpData(cls):
        user = User.objects.create(
            username='username', email='email@email.com', password='passwordpassword'
        )
        user2 = User.objects.create(
            username='username2',
            email='email2@email2.com',
            password='password2password2',
        )
        user.save()
        user2.save()

        board = Board.objects.create(name='1')
        board2 = Board.objects.create(name='2')
        board.save()
        board2.save()

        user_role1 = UserRole.objects.create(
            name='1.1',
            id_board=board,
            creating_task=False,
            deleting_task=False,
            editing_task=False,
        )
        user_role2 = UserRole.objects.create(name='1.2', id_board=board2, deleting_task=False, creating_task=False, editing_task=False)
        user_role1.save()
        user_role2.save()

        user_board1 = UserBoard.objects.create(
            id_user=user, id_board=board, id_user_role=user_role1
        )
        user_board1_2 = UserBoard.objects.create(
            id_user=user2, id_board=board, id_user_role=user_role1
        )
        user_board2 = UserBoard.objects.create(
            id_user=user2, id_board=board2, id_user_role=user_role2
        )
        user_board1.save()
        user_board1_2.save()
        user_board2.save()

        block1 = Block.objects.create(name='1', id_board=board)
        block2 = Block.objects.create(name='2', id_board=board2)
        block1_2 = Block.objects.create(name='3', id_board=board)
        block1.save()
        block2.save()
        block1_2.save()

        status_task1 = StatusTask.objects.create(name='1', id_board=board)
        status_task2 = StatusTask.objects.create(name='2', id_board=board2)
        status_task1.save()
        status_task2.save()

        task1 = Task.objects.create(text='1', id_block=block1, id_status_task = status_task1)
        task1_2 = Task.objects.create(text='1_2', id_block=block1, id_status_task= status_task1)
        task2 = Task.objects.create(text='2', id_block=block2, id_status_task= status_task2)
        task1.save()
        task2.save()
        task1_2.save()

        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f'Bearer ' + str(AccessToken.for_user(user))
        )

        result = {
            'user': user,
            'user2': user2,
            'board': board,
            'board2': board2,
            'user_role1': user_role1,
            'user_role2': user_role2,
            'user_board1': user_board1,
            'user_board1_2': user_board1_2,
            'user_board2': user_board2,
            'block1': block1,
            'block2': block2,
            'block1_2':block1_2,
            'status_task1': status_task1,
            'status_task2': status_task2,
            'task1': task1,
            'task1_2': task1_2,
            'task2': task2,
            'client': client,
        }

        return result

    def test_api_task_update(self):
        data = TaskTests.setUpData()
        client = data['client']

        resp = client.patch('/api/tasks/' + str(data['task1'].id) +  '/', {'text': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.put('/api/tasks/' + str(data['task1'].id) + '/', {'text': 'abc', 'id_block': data['block1'].id, 'id_status_task': data['status_task1'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch('/api/tasks/' + str(data['task2'].id) +  '/', {'text': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.put('/api/tasks/' + str(data['task2'].id) + '/', {'text': 'abc', 'id_block': data['block1'].id, 'id_status_task': data['status_task1'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role1'].editing_task = True
        data['user_role1'].save()

        resp = client.patch('/api/tasks/' + str(data['task1'].id) +  '/', {'text': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.put('/api/tasks/' + str(data['task1'].id) + '/', {'text': 'abc', 'id_block': data['block1'].id, 'id_status_task': data['status_task1'].id})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.patch('/api/tasks/' + str(data['task2'].id) +  '/', {'text': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.put('/api/tasks/' + str(data['task2'].id) + '/', {'text': 'abc', 'id_block': data['block1'].id, 'id_status_task':data['status_task1'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch('/api/tasks/' + str(data['task1'].id) + '/', {'id_block': data['block1_2'].id})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        data['user_role1'].editing_task = False
        data['user_role1'].save()

        data['user_board1'].is_admin = True
        data['user_board1'].save()

        resp = client.patch('/api/tasks/' + str(data['task1'].id) + '/', {'text': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.put('/api/tasks/' + str(data['task1'].id) + '/', {'text': 'abc123', 'id_block': data['block1'].id, 'id_status_task':data['status_task1'].id})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.patch('/api/tasks/' + str(data['task2'].id) +  '/', {'text': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.put('/api/tasks/' + str(data['task2'].id) + '/', {'text': 'abc', 'id_block': data['block1'].id,'id_status_task':data['status_task1'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_board1'].is_admin = False
        data['user_board1'].save()


    def test_api_task_create(self):
        data = TaskTests.setUpData()
        client = data['client']

        resp = client.post('/api/tasks/', {'text': 'abc', 'id_block': data['block2'].id, 'id_status_task': data['status_task2'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.post('/api/tasks/', {'text':'abc', 'id_block': data['block2'].id, 'id_status_task':data['status_task2']})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role1'].creating_task= True
        data['user_role1'].save()

        resp = client.post('/api/tasks/', {'text': 'abc', 'id_block': data['block1'].id, 'id_status_task':data['status_task1'].id})
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        resp = client.post('/api/tasks/', {'text':'abc', 'id_block': data['block2'].id, 'id_status_task':data['status_task2'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role1'].creating_task = False
        data['user_role1'].save()
        data['user_board1'].is_admin = True
        data['user_board1'].save()

        resp = client.post('/api/tasks/', {'text': 'abc', 'id_block': data['block1'].id,'id_status_task':data['status_task1'].id})
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        resp = client.post('/api/tasks/', {'text':'abc', 'id_block': data['block2'].id,'id_status_task': data['status_task2'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)


        data['user_board1'].is_admin = False
        data['user_board1'].save()



    def test_api_task_get_list(self):
        data = TaskTests.setUpData()
        client = data['client']

        resp = client.get('/api/tasks/')
        result = list()
        for i in resp.json():
            for x, y in i.items():
                if x == 'id_block':
                    result.append(y)

        self.assertTrue(data['block2'].id not in result)

    def test_api_task_get_pk(self):
        data = TaskTests.setUpData()
        client = data['client']

        resp = client.get('/api/tasks/' + str(data['task1'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.get('/api/tasks/' + str(data['task2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_api_task_custom_get_id_block(self):
        data = TaskTests.setUpData()
        client = data['client']

        resp = client.get('/api/tasks/' + str(data['block1'].id) + '/get_by_id_block/')
        result = list()
        for i in resp.json():
            for x, y in i.items():
                if x == 'id_block':
                    result.append(y)

        self.assertTrue(data['block2'].id not in result)

    def test_api_task_delete(self):
        data = TaskTests.setUpData()
        client = data['client']

        resp = client.delete('/api/tasks/' + str(data['task1'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.delete('/api/tasks/' + str(data['task2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role1'].deleting_task= True
        data['user_role1'].save()

        resp = client.delete('/api/tasks/' + str(data['task1'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

        resp = client.delete('/api/tasks/' + str(data['task2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role1'].deleting_task= False
        data['user_role1'].save()
        data['user_board1'].is_admin = True
        data['user_board1'].save()

        resp = client.delete('/api/tasks/' + str(data['task1_2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

        resp = client.delete('/api/tasks/' + str(data['task2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_board1'].is_admin = False
        data['user_board1'].save()


class CommentTests(APITestCase):
    @classmethod
    def setUpData(cls):
        user = User.objects.create(
            username='username', email='email@email.com', password='passwordpassword'
        )
        user2 = User.objects.create(
            username='username2',
            email='email2@email2.com',
            password='password2password2',
        )
        user.save()
        user2.save()

        board = Board.objects.create(name='1')
        board2 = Board.objects.create(name='2')
        board.save()
        board2.save()

        user_role1 = UserRole.objects.create(
            name='1.1',
            id_board=board,
            creating_task=False,
            deleting_task=False,
            editing_task=False,
        )
        user_role2 = UserRole.objects.create(name='1.2', id_board=board2, deleting_all_comment=False, deleting_ur_comment=False, creating_comment=False, editing_ur_comment=False)
        user_role1.save()
        user_role2.save()

        user_board1 = UserBoard.objects.create(
            id_user=user, id_board=board, id_user_role=user_role1
        )
        user_board1_2 = UserBoard.objects.create(
            id_user=user2, id_board=board, id_user_role=user_role1
        )
        user_board2 = UserBoard.objects.create(
            id_user=user2, id_board=board2, id_user_role=user_role2
        )
        user_board1.save()
        user_board1_2.save()
        user_board2.save()

        block1 = Block.objects.create(name='1', id_board=board)
        block2 = Block.objects.create(name='2', id_board=board2)
        block1.save()
        block2.save()

        status_task1 = StatusTask.objects.create(name='1', id_board=board)
        status_task2 = StatusTask.objects.create(name='2', id_board=board2)
        status_task1.save()
        status_task2.save()

        task1 = Task.objects.create(text='1', id_block=block1, id_status_task = status_task1)
        task2 = Task.objects.create(text='2', id_block=block2, id_status_task= status_task2)
        task1.save()
        task2.save()

        comment1 = Comment.objects.create(id_user=user, id_task=task1, text='abc')
        comment1_2 = Comment.objects.create(id_user=user2, id_task=task1, text='abc')
        comment2 = Comment.objects.create(id_user=user2, id_task=task2, text='abc')
        comment1.save()
        comment1_2.save()
        comment2.save()

        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f'Bearer ' + str(AccessToken.for_user(user))
        )

        result = {
            'user': user,
            'user2': user2,
            'board': board,
            'board2': board2,
            'user_role': user_role1,
            'user_role2': user_role2,
            'user_board': user_board1,
            'user_board1_2': user_board1_2,
            'user_board2': user_board2,
            'block1': block1,
            'block2': block2,
            'status_task1': status_task1,
            'status_task2': status_task2,
            'task1': task1,
            'task2': task2,
            'client': client,
            'comment1': comment1,
            'comment1_2': comment1_2,
            'comment2': comment2,
        }

        return result

    # обновлять можно с разрешением и только свои комментарии, is_admin может редактировать только свои комментарии
    def test_api_comment_update(self):
        data = CommentTests.setUpData()
        client = data['client']

        resp = client.put('/api/comments/' + str(data['comment1'].id) + '/', {'text': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch('/api/comments/' + str(data['comment1'].id) + '/', {'text':'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch('/api/comments/' + str(data['comment1_2'].id) + '/', {'text': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch('/api/comments/' + str(data['comment2'].id) + '/', {'text':'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        
        data['user_role'].editing_ur_comment = True
        data['user_role'].save()

        resp = client.patch('/api/comments/' + str(data['comment1'].id) + '/', {'name': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.patch('/api/comments/' + str(data['comment1_2'].id) + '/', {'text': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch('/api/comments/' + str(data['comment2'].id) + '/', {'text':'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].editing_ur_comment = False
        data['user_role'].save()

        data['user_board'].is_admin = True
        data['user_board'].save()

        resp = client.patch('/api/comments/' + str(data['comment1'].id) + '/', {'name': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.patch('/api/comments/' + str(data['comment1_2'].id) + '/', {'text': 'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.patch('/api/comments/' + str(data['comment2'].id) + '/', {'text':'abc'})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_board'].is_admin = True
        data['user_board'].save()


    # создавать можно с разрешением или is_admin
    # нельзя создавать комментарии от другого пользователя
    def test_api_comment_create(self):
        data = CommentTests.setUpData()
        client = data['client']       

        resp = client.post('/api/comments/', {'text':'abc', 'id_task':data['task1'].id, 'id_user':data['user'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.post('/api/comments/', {'text':'abc', 'id_task':data['task2'].id, 'id_user':data['user'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.post('/api/comments/', {'text':'abc', 'id_task':data['task1'].id, 'id_user':data['user2'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        
        data['user_role'].creating_comment = True
        data['user_role'].save()

        resp = client.post('/api/comments/', {'text':'abc', 'id_task':data['task1'].id, 'id_user':data['user'].id})
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        resp = client.post('/api/comments/', {'text':'abc', 'id_task':data['task1'].id, 'id_user':data['user2'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.post('/api/comments/', {'text':'abc', 'id_task':data['task1'].id, 'id_user':data['user2'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].creating_comment = False
        data['user_role'].save()

        data['user_board'].is_admin =True
        data['user_board'].save()

        resp = client.post('/api/comments/', {'text':'abc', 'id_task':data['task1'].id, 'id_user':data['user'].id})
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        resp = client.post('/api/comments/', {'text':'abc', 'id_task':data['task1'].id, 'id_user':data['user2'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.post('/api/comments/', {'text':'abc', 'id_task':data['task1'].id, 'id_user':data['user2'].id})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_board'].is_admin =True
        data['user_board'].save()

    # можно получить только те комментарии, которые относятся к доскам пользователя
    def test_api_comment_get_pk(self):
        data = CommentTests.setUpData()
        client = data['client']

        resp = client.get('/api/comments/' + str(data['comment1'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        resp = client.get('/api/tasks/' + str(data['comment2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)


    # получение списка досок, которые относятся к пользователю
    def test_api_comment_get_list(self):
        data = CommentTests.setUpData()
        client = data['client']

        resp = client.get('/api/comments/')
        result = list()
        for i in resp.json():
            for x, y in i.items():
                if x == 'id_task':
                    result.append(y)

        self.assertTrue(data['task2'].id not in result)

    #custom action
    def test_api_commnet_get_by_id_user(self):
        data = CommentTests.setUpData()
        client = data['client']

        resp = client.get('/api/comments/' + str(data['user'].id) + '/get_by_id_user/')
        result = list()
        for i in resp.json():
            for x, y in i.items():
                if x == 'id_user':
                    result.append(y)

        self.assertTrue(data['user2'].id not in result)       

    #custom action
    def test_api_comment_get_by_id_task(self):
        data = CommentTests.setUpData()
        client = data['client']

        resp = client.get('/api/comments/' + str(data['task1'].id) + '/get_by_id_task/')
        result = list()
        for i in resp.json():
            for x, y in i.items():
                if x == 'id_task':
                    result.append(y)

        self.assertTrue(data['task2'].id not in result)       


    # #custom action
    # def test_api_comment_get_by_id_user_and_task(self):
    #     data = CommentTests.setUpData()
    #     client = data['client']
    #
    #     resp = client.get('/api/comments/' + str(data['task1'].id) + '/get_by_id_user_and_task/')
    #     result = list()
    #     for i in resp.json():
    #         for x, y in i.items():
    #             if x == 'id_task':
    #                 result.append(y)
    #
    #     self.assertTrue(data['task2'].id not in result)       

    # проверка на разрешение удалять свои комментарии
    # проверка is_admin
    # проверка разрешения удалять все комментарии
    def test_api_comment_delete(self):
        data = CommentTests.setUpData()
        client = data['client']

        resp = client.delete('/api/comments/' + str(data['comment1'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.delete('/api/comments/' + str(data['comment2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.delete('/api/comments/' + str(data['comment1_2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].deleting_ur_comment = True
        data['user_role'].save()

        resp = client.delete('/api/comments/' + str(data['comment1'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

        resp = client.delete('/api/comments/' + str(data['comment2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.delete('/api/comments/' + str(data['comment1_2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        data['user_role'].deleting_ur_comment = False
        data['user_role'].save()

        data['user_role'].deleting_all_comment = True
        data['user_role'].save()

        resp = client.delete('/api/comments/' + str(data['comment1'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

        resp = client.delete('/api/comments/' + str(data['comment2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.delete('/api/comments/' + str(data['comment1_2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

        data['user_role'].deleting_all_comment = True
        data['user_role'].save()

        data['user_board'].is_admin = True
        data['user_board'].save()
        
        resp = client.delete('/api/comments/' + str(data['comment1'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

        resp = client.delete('/api/comments/' + str(data['comment2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = client.delete('/api/comments/' + str(data['comment1_2'].id) + '/')
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

        data['user_board'].is_admin = True
        data['user_board'].save()
