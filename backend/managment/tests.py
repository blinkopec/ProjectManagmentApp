from rest_framework.test import APIRequestFactory, APITestCase, APIClient
from .models import User
from rest_framework import status
from rest_framework.reverse import reverse

factory = APIRequestFactory()

class JWTTest(APITestCase):

    # Тест работы JWT
    def test_api_jwt(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(username=username,email=email,password=password)
        usr.is_active = False
        usr.save()

        resp = self.client.post(url, {'username': username, 'password': password}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

        usr.is_active = True
        usr.save()

        resp = self.client.post(url, {'username':username, 'password':password}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue('access' in resp.data)
        token = resp.data['access']

        verification_url = '/auth/jwt/verify/'
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
        url = '/auth/jwt/create/'
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(username=username,email=email,password=password)
        usr.save()

        resp = self.client.post(url, {'username':username, 'password':password}, format='json')
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.get('/api/users/' + str(usr.id) + '/', data={'format': 'json'})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        usr2 = User.objects.create_user(username='test2',email='test2@test.ru',password='test2')
        usr.save()

        resp = client.get('/api/users/' + str(usr2.id) + '/', data={'format': 'json'})
        self.assertNotContains(resp, 'login')
        self.assertNotContains(resp, 'password')

    # Тест регистрации
    def test_registration(self):
        url = '/auth/users/'
        username = 'test'
        email = 'test@mail.ru'
        password = 'test123213123'

        resp = self.client.post(url, { 'email': email, 'username': username, 'password': password}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    # Список пользователей не должен содержать в себе пароли и логины
    def test_user_list(self):
        url = '/auth/jwt/create/'
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(username=username,email=email,password=password)
        usr.save()

        resp = self.client.post(url, {'username':username, 'password':password}, format='json')
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
        usr = User.objects.create_user(username=username,email=email,password=password)
        usr.is_superuser = True
        usr_is_staff = True
        usr.save()

        resp = self.client.post(url, {'username':username, 'password':password}, format='json')
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.get('/api/users/' + str(usr.id) + '/', data={'format': 'json'})
        self.assertContains(resp, 'login')
        self.assertContains(resp, 'password')

        usr2 = User.objects.create_user(username='test2',email='test2@test.ru',password='test2')
        usr.save()

        resp = client.get('/api/users/' + str(usr2.id) + '/', data={'format': 'json'})
        self.assertContains(resp, 'login')
        self.assertContains(resp, 'password')

    # Пользователь может обновить информацию о себе
    def test_user_update_info(self):
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(username=username,email=email,password=password)
        usr.save()

        resp = self.client.post(url, {'username':username, 'password':password}, format='json')
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = self.client.put('/api/users/' + str(usr.id) + '/', {
            "username": "abc",
            "password": usr.password,
            "is_superuser": usr.is_superuser,
            "first_name": usr.first_name,
            "last_name": usr.last_name,
            "email": usr.email,
            "is_staff": usr.is_staff
        })

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # Обычный пользователь не может создавать новых пользователей
    def test_user_create_users(self):
        url = '/auth/jwt/create/'
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(username=username,email=email,password=password)
        usr.save()

        resp = self.client.post(url, {'username':username, 'password':password}, format='json')
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.post('/api/users/', {'username': 'test2', 'email': 'test2@test.ru', 'password': 'test2', 'is_superuser': False}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # Супер пользователь может создавать новых пользователей
    def test_superuser_create_users(self):
        url = '/auth/jwt/create/'
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(username=username,email=email,password=password)
        usr.is_superuser = True
        usr.save()

        resp = self.client.post(url, {'username':username, 'password':password}, format='json')
        token = resp.data['access']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer ' + token)

        resp = client.post('/api/users/', {'username': 'test2', 'email': 'test2@test.ru', 'password': 'test2',
         'is_superuser': False, "is_staff": "True", "last_name": "asdsad", "first_name": "asd",}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    
class StatusTaskTests(APITestCase):

    # Выдача списка авторизованному 
    def test_api_status_task_list_auth(self):
        url = '/auth/jwt/create/'
        url = '/auth/jwt/create/'
        username = 'test'
        email = 'test@test.ru'
        password = 'test'
        usr = User.objects.create_user(username=username,email=email,password=password)
        usr.save()

        resp = self.client.post(url, {'username':username, 'password':password}, format='json')
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
    
    # супер пользователь должен иметь дсотуп к PUT и DELETE
    def test_api_status_task_superuser(self):
        pass

