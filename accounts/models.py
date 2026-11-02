from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    """
    Custom manager for our User model.
    Required because Django's default manager uses 'username', but we use 'email'.
    """

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")

        # Normalize email: lower-case the domain part
        email = self.normalize_email(email)

        # Create the user instance
        user = self.model(email=email, **extra_fields)

        # Hash the password securely
        user.set_password(password)

        # Save to database
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        # Set default flags for superuser
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_email_verified", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model using email as the unique identifier.
    """

    class Role(models.TextChoices):
        USER = "USER", "User"
        ADMIN = "ADMIN", "Admin"

    email = models.EmailField(unique=True, db_index=True, verbose_name="email address")
    full_name = models.CharField(max_length=150, blank=True)

    is_active = models.BooleanField(default=True)
    is_email_verified = models.BooleanField(default=False)

    is_staff = models.BooleanField(default=False)

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.USER,
    )

    date_joined = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    # Connect the custom manager
    objects = UserManager()

    # Use email to log in
    USERNAME_FIELD = "email"

    # No other fields required when creating a superuser via CLI
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email
