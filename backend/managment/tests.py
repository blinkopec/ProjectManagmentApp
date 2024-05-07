from django.contrib.auth.base_user import password_validation
from django.http import Http404  # для закрытия не сделанных тестов (УБРАТЬ)
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APIClient, APIRequestFactory, APITestCase

from .models import Board, StatusTask, User, UserBoard, UserRole

factory = APIRequestFactory()

# user = User.objects.create_user(username='test', email='test@test.ru', password='test')
# user2 = User.objects.create_user(
#     username='test2', email='testw@test.ru', password='test2'
# )
# board = Board.objects.create(name='test')
# user_role = UserRole.objects.create(
#     name='test',
#     id_board=board.id,
#     creating_role=True,
#     editing_role=True,
#     deleting_role=True,
# )
# user_board = UserBoard.objects.create(
#     id_user=user.id, id_board=board.id, id_user_role=user_role.id
# )
# user.save()
# user2.save()
# board.save()
# user_role.save()
# user_board.save()
# resp = self.client.post('/auth/jwt/create/', {user.name, user.password}, format='json')
# client = APIClient()
# client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + resp.data[access])
#


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


class StatusTaskTests(APITestCase):

    # Выдача списка авторизованному
    def test_api_status_task_list_auth(self):
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

        resp = client.get('/api/status_tasks/', data={'format': 'json'})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # Не авторизованный юзер не может получить список
    def test_api_status_task_list_nonauth(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + 'abc')

        resp = client.get('/api/status_tasks/', data={'format': 'json'})
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    # супер пользователь иммет досутп к patch
    def test_api_status_task_superuser(self):
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

        st_task = StatusTask.objects.create(name='test')

        resp = client.patch(
            '/api/status_tasks/' + str(st_task.id) + '/', {'name': 'abc'}
        )

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # супер пользователь иммет досутп к put
    def test_api_status_task_superuser_put(self):
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

        st_task = StatusTask.objects.create(name='test')

        resp = client.put('/api/status_tasks/' + str(st_task.id) + '/', {'name': 'abc'})

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # пользователь сотрудник (is_staff) имеет доступ к patch
    def test_api_status_task_staff_patch(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password, is_staff=True
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        st_task = StatusTask.objects.create(name='test')

        resp = client.patch(
            '/api/status_tasks/' + str(st_task.id) + '/', {'name': 'abc'}
        )

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        usr.delete()

    # пользователь сотрудник (is_staff) имеет доступ к put
    def test_api_status_task_staff_put(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(
            username=username, email=email, password=password, is_staff=True
        )
        usr.save()

        resp = self.client.post(
            url, {'username': username, 'password': password}, format='json'
        )
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        st_task = StatusTask.objects.create(name='test')

        resp = client.put('/api/status_tasks/' + str(st_task.id) + '/', {'name': 'abc'})

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        usr.delete()


class UserRoleTests(APITestCase):
    # user = User.objects.create_user(
    #     username='test', email='test@test.ru', password='test'
    # )
    # user2 = User.objects.create_user(
    #     username='test2', email='testw@test.ru', password='test2'
    # )
    # board = Board.objects.create(name='test')
    # user_role = UserRole.objects.create(
    #     name='test',
    #     id_board=board.id,
    #     creating_role=True,
    #     editing_role=True,
    #     deleting_role=True,
    # )
    # user_board = UserBoard.objects.create(
    #     id_user=user.id, id_board=board.id, id_user_role=user_role.id
    # )
    # user.save()
    # user2.save()
    # board.save()
    # user_role.save()
    # user_board.save()
    # resp = self.client.post(
    #     '/auth/jwt/create/', {user.name, user.password}, format='json'
    # )
    # client = APIClient()
    # client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + resp.data[access])

    # тест на проверку создания роли
    def test_api_user_role_creating_with_true(self):
        resp = client.post(
            '/api/user_roles/', {'name': 'test', 'id_board': board.id}, format='json'
        )
        self.assertEqual(resp.status, status.HTTP_201_CREATED)

        user_role.creating_role = False
        user_role.save()

        resp = client.post(
            'api/user_roles', {'name': 'test', 'id_board': board.id}, format='json'
        )


# тест на ввод неправильного id_board
# тест на редактирование с разрешением
# тест на редактирование без разрешения
# тест на удаление с разрешением
# тест на удаление без разрешения
