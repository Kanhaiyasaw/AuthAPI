from rest_framework import serializers
from account.models import User
from xml.dom import ValidationErr
from account.utils import Util
from django.utils.encoding import (smart_str,
                                    force_bytes,
                                    DjangoUnicodeDecodeError
                                    )
from django.utils.http import (urlsafe_base64_decode,
                                urlsafe_base64_encode
                                )
from django.contrib.auth.tokens import PasswordResetTokenGenerator   



class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password','write_only':True})
    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs = {
           'password':{'write_only':True} 
        }
    # Validate password and confirm password while registration process
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and confirm password doesn't match")
        return data
        
    # Creating User
    def create(self, validate_data):
        return User.objects.create_user(**validate_data)

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'tc']

class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input-type':'password'}, write_only = True, max_length=200)
    password2 = serializers.CharField(style={'input-type':'password'}, write_only = True, max_length=200)
    class Meta:
        model = User
        field = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
             raise serializers.ValidationError("Password and confirm password doesn't match")
        user.set_password(password)
        user.save()
        return attrs

class UserPasswordresetEmailSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255)
    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded Id', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset token', token)
            link = 'http://127.0.0.1:8000/api/user/resetpassword/'+uid+'/'+token
            print('Reset Link ', link)
            #Send Email
            body = "Click following link to reset your password : "+ link
            data = {
                "subject" : "Reset Your Password",
                "body" : body,
                "to_email" : user.email
            }
            Util.send_email(data)
            return attrs    
        else:
            raise ValidationErr('You Are not Registered User')

class UserResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input-type':'password'}, write_only = True, max_length=200)
    password2 = serializers.CharField(style={'input-type':'password'}, write_only = True, max_length=200)
    class Meta:
        model = User
        field = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password and confirm password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationErr('Token is not valid or Expire')
            user.set_password(password)
            user.save() 
            return attrs
        except DjangoUnicodeDecodeError:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationErr('Token is not valid or Expire')

