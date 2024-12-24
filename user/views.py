

from rest_framework.views import APIView

from django.conf import settings
import jwt
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework_simplejwt.tokens import RefreshToken
from cback.settings import AUTH0_DOMAIN
from user.models import User
from .serializers import RegisterSerializer, LoginSerializer
from django.http import JsonResponse
import logging
import requests
from jose import JWTError, jwt
logger = logging.getLogger(__name__)
AUTH0_AUDIENCE = 'WCjafQ8oP9mB45jeQdxH8Y03bkgRySei'

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)

            response = JsonResponse({
                'message': 'Login exitoso',
            })
            response.set_cookie(
                key='access_token',
                value=str(refresh.access_token),
                httponly=True,  
                secure=True,  
                samesite='Lax',  
            )
            response.set_cookie(
                key='refresh_token',
                value=str(refresh),
                httponly=True,
                secure=True,
                samesite='Lax',
            )

            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GoogleLoginView(generics.GenericAPIView):
    def verify_auth0_token(self, token):
        try:
         
            header = jwt.get_unverified_header(token)
            if 'kid' not in header:
                raise JWTError('No kid in header')

         
            jwks_url = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
            response = requests.get(jwks_url)
            jwks = response.json()

            rsa_key = {}
            for key in jwks['keys']:
                if key['kid'] == header['kid']:
                    rsa_key = {
                        'kty': key['kty'],
                        'kid': key['kid'],
                        'use': key['use'],
                        'n': key['n'],
                        'e': key['e']
                    }

            if not rsa_key:
                raise JWTError('No matching key found')

           
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=['RS256'], 
                audience= AUTH0_AUDIENCE,
                options={"verify_iss": True, "verify_aud": True}  
            )

            return payload
        except JWTError as e:
            logger.error(f"Error en la verificación del token de Auth0: {e}")
            raise
        except Exception as e:
            logger.error(f"Ocurrió un error inesperado: {e}")
            raise
    def post(self, request):
        token = request.data.get('token')
       
        print(token)
        if not token:
            return Response({'error': 'No token provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
 
            payload = self.verify_auth0_token(token)  
            email = payload['email']

            user, created = User.objects.get_or_create(email=email)
            if created:
                user.set_unusable_password()
                user.save()
                logger.info(f"Usuario creado para el email: {email}")
            refresh = RefreshToken.for_user(user)
            logger.info(f"JWT tokens generados para el usuario {user.id}")

            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
            }, status=status.HTTP_200_OK)

        except JWTError as e:
            logger.error(f"Error al verificar el token de Google: {str(e)}")
            return Response({'error': f'Token inválido: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error al procesar la solicitud: {str(e)}")
            return Response({'error': 'Error procesando la solicitud.'}, status=status.HTTP_400_BAD_REQUEST)

  