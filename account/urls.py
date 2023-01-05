from django.urls import path
from account.views import   (UserRegistrationView,
                            UserLoginView,
                            UserProfileView,
                            UserChangePasswordView,
                            UserPasswordRestEmailView,
                            UserResetPasswordView
                            )

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name="register"),
    path('login/', UserLoginView.as_view(), name="login"),
    path('profile/', UserProfileView.as_view(), name="profile"),
    path('changepassword/', UserChangePasswordView.as_view(), name="changepassword"),
    path('send-reset-password-email/', UserPasswordRestEmailView.as_view(), name="send-reset-password-email"),
    path('resetpassword/<uid>/<token>/', UserResetPasswordView.as_view(), name="resetpassword")
]
