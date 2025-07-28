from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from .models import User


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True, required=True)
    first_name = serializers.CharField(required=True, max_length=150)
    last_name = serializers.CharField(required=True, max_length=150)

    class Meta:
        model = User
        fields = ('id', 'email', 'password', 'password_confirm', 'first_name', 'last_name')
        read_only_fields = ('id',)

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        # Set user_type to 'provider' for all registrations through this serializer
        validated_data['user_type'] = 'provider'
        user = User.objects.create_user(**validated_data)
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'email_verified', 'phone_number', 'phone_number_verified',
                 'mfa_totp_setup_complete', 'mfa_email_enabled', 'mfa_sms_enabled', 'date_joined', 'last_login')
        read_only_fields = ('id', 'email', 'date_joined', 'last_login', 'email_verified', 'phone_number_verified',
                           'mfa_totp_setup_complete', 'mfa_email_enabled', 'mfa_sms_enabled')


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({"new_password": "Password fields didn't match."})
        return attrs


class MFASetupSerializer(serializers.Serializer):
    code = serializers.CharField(required=True, min_length=6, max_length=6) 