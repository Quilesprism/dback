import re
from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from django.contrib.auth import get_user_model

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, value):
       
        if len(value) < 8 or not re.findall(r'[A-Z]', value) or not re.findall(r'[0-9]', value):
            raise serializers.ValidationError(
                'La contraseña debe tener al menos 8 caracteres, incluyendo un número y una letra mayúscula.')
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            validated_data['email'],
            validated_data['password']
        )
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        User = get_user_model()
        user = User.objects.filter(email=data['email']).first()

        if user and user.check_password(data['password']):
            if not user.is_active:
                raise serializers.ValidationError("Esta cuenta está deshabilitada.")
            return user
        raise serializers.ValidationError("Credenciales incorrectas")

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email',)
