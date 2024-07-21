import uuid
import io
import os
import csv
import random
import string
from datetime import timedelta
from reportlab.pdfgen import canvas
from django.core.mail import send_mail
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.utils.encoding import smart_str
from reportlab.lib.pagesizes import letter
from django.http import Http404
from django.http import HttpResponse
from django.contrib.auth.models import Group, Permission
from django.shortcuts import get_object_or_404
from django.core.validators import validate_email
from django.http import JsonResponse
from django.contrib.contenttypes.models import ContentType
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.contrib.auth import logout
from django.contrib.auth.models import User, Permission
from django.core.exceptions import ValidationError
from django.template.loader import render_to_string
from django.contrib.auth.hashers import check_password
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.exceptions import ValidationError
from rest_framework.exceptions import ValidationError
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework import status, generics
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .utils import (
    vaildate_email_address,
    create_tenant_response,
    genrate_rendom_code,
    genrate_otp_save_to_db,
    Send_email_via_template,
    generate_tokens,
    verifyOTP,
    passowdvaildation,
    validate_and_confirm_passwords,
    check_permissions_exist,
)
from Rest_api import settings
from .serializers import (
    RegisterUserSerializer,
    VerifiedOtpSerializer,
    ProjectSerializer,
    RiskSerializer,
    VulnerabilitySerializer,
    UserSerializer,
    UserCustomSerializer,
    PermissionSerializer,
    ScanSerializer,
    RisksSerializer,
    TargetSerializer,
    UserLoginSerializer,
    TenantUserSerializer,
    GroupSerializer,
    ChangePasswordSerializer,
    TenantSerializer,
    
)
from .models import (
    Scan,
    Risks,
    Project,
    UserCustom,
    Risk,
    TenantUser,
    Target,
    User,
    UserOtp,
)
from .serializers import ChangePasswordSerializer
from .serializers import ChangePasswordSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated



@api_view(["POST"])
def register_user(request):
    """
        View function to handle user registration.
        Parameters:
        - request: The HTTP request object containing user email and password.
        Returns:
        - If the registration is successful and OTP is sent, returns a success response.
        - If there is an issue with SMTP mail, returns an error response with status code 201.
        - If the request method is not POST, returns an error response with status code 405.
    """
    if request.method == "POST":
        validate_email = vaildate_email_address(request.data.get("email"))
        if not validate_email:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Please enter a correct email address",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        is_valid, errors = passowdvaildation(request.data.get("password"))
        if not is_valid:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            user, tenant_data = serializer.save()
            mfa_code = genrate_rendom_code(6)
            user_opt = {"otp": mfa_code, "is_active": True, "useruuid": user.id}
            optResp = genrate_otp_save_to_db(user_opt, "OTP Generated Successfully")
            if optResp.data["type"] == "success":
                html_content = render_to_string( "email/user/otp_email_template.html", {"otp": mfa_code})
                send_email_Resp = Send_email_via_template("Verification Code", html_content, [request.data.get("email")])
                if send_email_Resp:
                    return Response(
                            {
                                "code": status.HTTP_201_CREATED,
                                "type": "success",
                                "message": "User registered successfully. Verification code sent to your email.",
                                "id": user.id,
                                "data": tenant_data
                            },
                            status=status.HTTP_201_CREATED,
                        )
                return Response(
                            {
                                "code": status.HTTP_201_CREATED,
                                "type": "success",
                                "message": "User registered successfully. SMTP Mail Issue",
                             "data": tenant_data
                            },
                            status=status.HTTP_201_CREATED,
                        )               
            return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "type": "error",
                        "message": "Something wrong",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "type": "error",
                        "message": serializer.errors,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )        
    else:
        return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "error",
                "message": "Only POST requests are allowed",
                "data": {},
            },
            status=status.HTTP_400_BAD_REQUEST,
        )





@api_view(["POST"])
def login(request):
    """
    View function to handle user login.
    Parameters:
    - request: The HTTP request object containing user email and password.
    Returns:
    - If the login is successful and OTP is sent, returns a success response.
    - If the email format is incorrect, returns an error response with status code 400.
    - If the password validation fails, returns an error response with status code 400.
    - If the request method is not POST, returns an error response with status code 405.
    """
    if request.method == "POST":
        validate_email = vaildate_email_address(request.data.get("email"))
        if not validate_email:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Please enter a correct email address",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        is_valid, errors = passowdvaildation(request.data.get("password"))
        if not is_valid:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = UserLoginSerializer(data=request.data)
        # serializer = RegisterUserSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data["user"]
            request.session["user_id"] = user.id
            mfa_code = genrate_rendom_code(6)
            user_opt = {"otp": mfa_code, "is_active": True, "useruuid": user.id}
            optResp = genrate_otp_save_to_db(user_opt, "Otp Genrated SucessFully")

            if optResp.data["type"] == "success":
                html_content = render_to_string(
                    "email/user/login_opt_template.html", {"otp": mfa_code}
                )
                send_email_Resp = Send_email_via_template(
                    "Verification Code", html_content, [request.data.get("email")]
                )
                if send_email_Resp:
                    return Response(
                        {
                            "code": status.HTTP_200_OK,
                            "type": "success",
                            "message": "User Logged-in successfully. Verification code sent to your email.",
                        },
                        status=status.HTTP_200_OK,
                    )
                else:
                    return Response(
                        {
                            "code": status.HTTP_200_OK,
                            "type": "success",
                            "message": "User Logged-in successfully. SMTP Mail Issue",
                        },
                        status=status.HTTP_200_OK,
                    )
            else:
                return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "type": "error",
                        "message": "Something wrong",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
    else:
        return Response(
            {
                "code": status.HTTP_405_METHOD_NOT_ALLOWED,
                "type": "error",
                "message": "Only POST requests are allowed",
            },
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )


@api_view(["POST"])
def verify_otp(request, user_id):
    """
    View function to verify the OTP (One Time Password) submitted by the user.
    Parameters:
    - request: The HTTP request object containing the OTP.
    - user_id: The ID of the user to verify the OTP for.
    Returns:
    - If OTP verification is successful, returns an access token.
    - If OTP verification fails, returns an error response with status code 400.
    - If the request method is not POST, returns an error response with status code 405.
    """
    if request.method == "POST":
        serializer = VerifiedOtpSerializer(data=request.data, context={'user_id': user_id})
        if serializer.is_valid():
            serializeraccess_token = serializer.validated_data
            if serializeraccess_token : 
                access_token = generate_tokens(user_id)
                if access_token.data["type"] == "success":
                    return access_token
        else:
            return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "error",
                "message": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "error",
                "message": "Only POST requests are allowed",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def logout_user(request):
    """
    View function to handle user logout and invalidate tokens.
    Parameters:
    - request: The HTTP request object.
    Returns:
    - If the user is successfully logged out and tokens are invalidated, returns a success response.
    - If there is an error during the logout process, returns an error response with status code 400.
    """
    try:
        access_token = request.data.get("access_token")
        refresh_token = request.data.get("access_token")
        if access_token:
            # Flush the session to log the user out
            request.session.flush()

            token = AccessToken(access_token)
            token.blacklist()

            tokens = OutstandingToken.objects.filter(user=token.user)
            tokens.delete()

            logout(request)
        return Response(
            {
                "code": status.HTTP_200_OK,
                "type": "success",
                "message": "User logged out and tokens invalidated successfully",
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        return Response(
            {"code": status.HTTP_400_BAD_REQUEST, "type": "success", "message": str(e)},
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
def forgot_password(request):
    """
    View function to handle the forgot password functionality.
    Parameters:
    - request: The HTTP request object containing user email.
    Returns:
    - If the password reset OTP is successfully generated and sent to the user's email, returns a success response.
    - If the user email is invalid or not found, returns an error response with status code 400.
    - If there is an issue with SMTP mail, returns an error response with status code 201.
    - If the request method is not POST, returns an error response with status code 405.
    """
    if request.method == "POST":
        validate_email = vaildate_email_address(request.data.get("email"))
        if not validate_email:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Please enter a correct email address",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            user = User.objects.get(email=request.data.get("email"))
            pass
        except User.DoesNotExist:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "User not found",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Generate a random OTP
        mfa_code = genrate_rendom_code(6)
        user_opt = {"otp": mfa_code, "is_active": True, "useruuid": user.id}
        optResp = genrate_otp_save_to_db(user_opt, "Otp Genrated SucessFully")
        if optResp.data["type"] == "success":
            html_content = render_to_string(
                "email/user/reset_password.html",
                {"verification_code": mfa_code, "user_email": user.email},
            )
            send_email_Resp = Send_email_via_template(
                "Verification Code", html_content, [request.data.get("email")]
            )

            if send_email_Resp:
                return Response(
                    {
                        "code": status.HTTP_200_OK,
                        "type": "success",
                        "message": "Forgot Password verification code sent to your email.",
                    },
                    status=status.HTTP_200_OK,
                )
            else:

                return Response(
                    {"code": "success", "message": "SMTP Mail Issue "},
                    status=status.HTTP_201_CREATED,
                )
        else:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "success",
                    "message": "Something Wrong",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
    else:
        return Response(
            {
                "code": status.HTTP_405_METHOD_NOT_ALLOWED,
                "type": "success",
                "message": "Method not allowed",
            },
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )


@api_view(["POST"])
def resetpass(request):
    """
    View function to reset the user's password.
    Parameters:
    - request: The HTTP request object containing the email, new_password, confirm_password, and OTP.
    Returns:
    - If the password reset is successful, returns a success response.
    - If there are validation errors (e.g., incorrect email format, weak password), returns error messages with status code 400.
    - If the OTP is invalid or expired, returns an error response with status code 400.
    - If the request method is not POST, returns an error response with status code 405.
    """

    if request.method == "POST":

        email = request.data.get("email")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")
        otp = request.data.get("otp")
        validate_email = vaildate_email_address(email)
        if not validate_email:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Please enter a correct email address",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        is_valid, errors = validate_and_confirm_passwords(
            new_password, confirm_password
        )
        if not is_valid:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        # return Response({"code": status.HTTP_400_BAD_REQUEST,"type": 'error',"message": 'errors'},status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
            verify_req = verifyOTP(otp)
            if verify_req.data["type"] == "success":
                user.set_password(new_password)
                user.save()
                return Response(
                    {
                        "code": status.HTTP_200_OK,
                        "type": "success",
                        "message": "Password Changed Successfully",
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "type": "error",
                        "message": "Invalid or expired OTP!! Please enter the correct OTP",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except User.DoesNotExist:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "User with this email does not exist",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": str(e),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
    else:
        return Response(
            {
                "code": status.HTTP_405_METHOD_NOT_ALLOWED,
                "type": "error",
                "message": "Method not allowed",
            },
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )



@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def fetch_own_profile(request):
    """
    Endpoint to fetch the profile of the currently authenticated user.
    """
    user = request.user
    return Response(
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        }
    )

User = get_user_model()
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data["old_password"]
            new_password = serializer.validated_data["new_password"]
            user = User.objects.get(pk=user.pk)
            if not check_password(old_password, user.password):
                return Response(
                    {"error": "Incorrect old password."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user.set_password(new_password)
            user.save()
            return Response(
                {"success": "Password changed successfully."}, status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def user_list_create(request):
    """
    Handle GET and POST requests for listing and creating users.

    Args:
    - request: The HTTP request object.

    Returns:
    - Response: A JSON response containing either a list of serialized users
      (in case of a GET request) or the serialized data of the created user
      (in case of a POST request).

    GET Request:
        Retrieves a list of serialized users.

    POST Request:
        Creates a new user using provided data. If the user is not authenticated,
        returns a 401 Unauthorized response.

    """
    if request.method == "GET":
        users = UserCustom.objects.filter(is_active=True)
        serializer = UserCustomSerializer(users, many=True)
        return Response(serializer.data)

    elif request.method == "POST":
        if not request.user.is_authenticated:
            return Response(
                {
                    "code": status.HTTP_401_UNAUTHORIZED,
                    "type": "error",
                    "message": "Authentication credentials were not provided.",
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        serializer = UserCustomSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "code": status.HTTP_201_CREATED,
                    "type": "success",
                    "message": "user successfully created",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "error",
                "message": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["GET", "PUT", "PATCH", "DELETE"])
def user_detail(request, pk, **kwargs):
    """
    Handle GET, PUT, PATCH, and DELETE requests for individual users.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the user.

    Returns:
    - Response: A JSON response containing the serialized data of the user
      (in case of a GET request), the updated serialized data of the user
      (in case of a PUT or PATCH request), or a success message indicating
      user deactivation (in case of a DELETE request).

    GET Request:
        Retrieve serialized data of the user.

    PUT or PATCH Request:
        Update the user's data with the provided data.

    DELETE Request:
        Deactivate the user by marking them as inactive.

    """
    try:
        user = UserCustom.objects.get(pk=pk)
    except UserCustom.DoesNotExist:
        return Response(
            {
                "code": status.HTTP_404_NOT_FOUND,
                "type": "error",
                "message": "User not found.",
            },
            status=status.HTTP_404_NOT_FOUND,
        )

    if request.method == "GET":
        print(user.is_active)
        if user.is_active == False:
            return Response(
                {
                    "code": status.HTTP_404_NOT_FOUND,
                    "type": "error",
                    "message": "User not found.",
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        else:
            serializer = UserCustomSerializer(user)
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "User retrieved successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

    elif request.method in ["PUT", "PATCH"]:
        if user.is_active == False:
            return Response(
                {
                    "code": status.HTTP_404_NOT_FOUND,
                    "type": "error",
                    "message": "User not found.",
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = UserCustomSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "user is updated",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "error",
                "message": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    elif request.method == "DELETE":
        if user.is_active == False:
            return Response(
                {
                    "code": status.HTTP_404_NOT_FOUND,
                    "type": "error",
                    "message": "User not found.",
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        else:
            try:
                user = UserCustom.objects.get(id=pk)
                pass
                # print("user id get", user)
            except UserCustom.DoesNotExist:
                return Response(
                    {
                        "code": status.HTTP_404_NOT_FOUND,
                        "type": "error",
                        "message": "User not found.",
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )
            # Soft delete: Mark user as inactive
            user.is_active = False
            user.save()
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "error",
                    "message": "User deactivated successfully.",
                },
                status=status.HTTP_200_OK,
            )


class TenantRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    A view for retrieving, updating, and deleting a specific Tenant_user instance.

    Supported HTTP Methods:
    - GET: Retrieve a specific Tenant_user instance or list all Tenant_user instances.
    - POST: Create a new Tenant_user instance.
    - PATCH: Update a specific Tenant_user instance.
    - DELETE: Delete a specific Tenant_user instance.

    Attributes:
    - queryset: The queryset of Tenant_user instances.
    - serializer_class: The serializer class used for Tenant_user instances.
    - lookup_field: The lookup field for retrieving Tenant_user instances.
    """

    queryset = TenantUser.objects.all()
    serializer_class = TenantUserSerializer
    lookup_field = "tenant_id"

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            instance = serializer.save()
            return Response(
                {
                    "code": status.HTTP_201_CREATED,
                    "type": "success",
                    "message": "Tenant is Successfully Created",
                    "data": [serializer.data],
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "error",
                "data": [serializer.errors],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    def get(self, request, *args, **kwargs):
        tenant_id = kwargs.get("tenant_id")
        if tenant_id:
            # Retrieve a specific instance if tenant_id is provided
            tenant_id = "".join(c for c in tenant_id if c.isalnum())
            try:
                tenant_uuid = uuid.UUID(tenant_id)
                tenant = get_object_or_404(TenantUser, tenant_id=tenant_uuid)
                serializer = TenantSerializer(instance=tenant)
                return JsonResponse(
                    {
                        "code": status.HTTP_200_OK,
                        "type": "success",
                        "message": "Tenant data retrieved successfully",
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            except (ValidationError, ValueError):
                return JsonResponse(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "type": "error",
                        "message": "Invalid UUID format",
                        "data": [],
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            # Retrieve all instances if no tenant_id is provided
            tenants = TenantUser.objects.all()
            serializer = TenantSerializer(tenants, many=True)
            return JsonResponse(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "All tenants data retrieved successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

    def patch(self, request, *args, **kwargs):
        tenant_id = kwargs.get("tenant_id")
        if tenant_id:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "code": status.HTTP_200_OK,
                        "type": "success",
                        "message": "Tenant is successfully updated",
                        "data": [serializer.data],
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "type": "success",
                        "message": serializer.errors,
                        "data": [],
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Provide the Tenant ID",
                    "data": [],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    def delete(self, request, *args, **kwargs):
        tenant_id = kwargs.get("tenant_id")
        if tenant_id:
            instance = get_object_or_404(TenantUser, tenant_id=tenant_id)
            instance.delete()
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "Tenant successfully deleted",
                    "data": [],
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "success",
                    "message": "Provide the Tenant ID",
                    "data": [],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class RoleRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    A view for retrieving, updating, and deleting a specific Tenant_user instance.

    Supported HTTP Methods:
    - GET: Retrieve a specific Tenant_user instance or list all Tenant_user instances.
    - POST: Create a new Tenant_user instance.
    - PATCH: Update a specific Tenant_user instance.
    - DELETE: Delete a specific Tenant_user instance.

    Attributes:
    - queryset: The queryset of Tenant_user instances.
    - serializer_class: The serializer class used for Tenant_user instances.
    """

    queryset = Group.objects.all()
    serializer_class = GroupSerializer

    def post(self, request, *args, **kwargs):
        group_name = request.data.get("name")
        permission_names = request.data.get("permission")
        # return Response({"code": status.HTTP_400_BAD_REQUEST,"type": permission_names,"message": "Role with this name already exists"},status=status.HTTP_400_BAD_REQUEST)
        if not group_name or not permission_names:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Role name and permissions are required",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            group = Group.objects.get(name=group_name)
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Role with this name already exists",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Group.DoesNotExist:
            pass
        # permission_names = ["Canasdsad", "Can add permission", "Can add user"]
        permissions_exist = check_permissions_exist(permission_names)
        if False in permissions_exist.values():
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Permission name is not Exist",
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # print(permissions_exist)
        try:

            group, created = Group.objects.get_or_create(name=group_name)
            group.permissions.clear()
            permissions = Permission.objects.filter(name__in=permission_names)
            if permissions.exists():
                for permission in permissions:
                    group.permissions.add(permission)
                serializer = GroupSerializer(group)
                return Response(
                    {
                        "code": status.HTTP_201_CREATED,
                        "type": "success",
                        "message": "Role created successfully and assocated with permission",
                        "data": serializer.data,
                    },
                    status=status.HTTP_201_CREATED,
                )
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "One or more permissions do not exist",
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Permission.DoesNotExist:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "One or more permissions do not exist",
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": str(e),
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    def get(self, request, *args, **kwargs):

        group_id = kwargs.get("pk")
        if group_id:
            try:
                group = get_object_or_404(Group, pk=group_id)
                serializer = GroupSerializer(group)
                return Response(
                    {
                        "code": status.HTTP_200_OK,
                        "type": "success",
                        "success": "Role retrieved successfully",
                        "data": [serializer.data],
                    },
                    status=status.HTTP_200_OK,
                )
            except Group.DoesNotExist:
                return Response(
                    {
                        "code": status.HTTP_404_NOT_FOUND,
                        "type": "error",
                        "message": "Role does not exist for this ID",
                        "data": {serializer.errors},
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:

            try:
                all_groups = Group.objects.all()

                serializer = GroupSerializer(all_groups, many=True)
                return Response(
                    {
                        "code": status.HTTP_200_OK,
                        "type": "success",
                        "success": "All Role retrieved successfully",
                        "groups": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            except Exception as e:
                return Response(
                    {
                        "code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                        "type": "error",
                        "message": str(e),
                        "data": {},
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

    def put(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        permission_names = request.data.get("permission")
        permissions_exist = check_permissions_exist(permission_names)
        if False in permissions_exist.values():
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Permission name is not Exist",
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(
            {
                "code": status.HTTP_200_OK,
                "type": "success",
                "success": "Role update and associated with permission",
                "groups": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    def patch(self, request, *args, **kwargs):
        kwargs["partial"] = True
        group_id = kwargs.get("pk")
        if group_id:
            group_name = request.data.get("name")
            permission_names = request.data.get("permission_names")
            if not group_name or not permission_names:
                return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "type": "error",
                        "message": "Role name and permissions are required",
                        "data": {},
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            try:
                group = get_object_or_404(Group, pk=group_id)
                pass 
            except Group.DoesNotExist:
                return Response(
                    {
                        "code": status.HTTP_404_NOT_FOUND,
                        "type": "error",
                        "message": "Role does not exist for this ID",
                        "data": {serializer.errors},
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            permissions_exist = check_permissions_exist(permission_names)
        if False in permissions_exist.values():
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Permission name is not Exist",
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            group = Group.objects.get(pk=group_id)
            # print("group :", group)
            group.permissions.clear()
            permissions = Permission.objects.filter(name__in=permission_names)
            group.permissions.add(*permissions)
            serializer = GroupSerializer(group)
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "success": "Role update and associated with permission",
                    "groups": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        except Group.DoesNotExist:
            return Response(
                {
                    "code": status.HTTP_404_NOT_FOUND,
                    "type": "error",
                    "message": "Group does not exist for this ID",
                    "data": {},
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        else:
            return Response(
                {
                    "code": status.HTTP_404_NOT_FOUND,
                    "type": "error",
                    "message": "Provide the Role  ID",
                    "data": {},
                },
                status=status.HTTP_404_NOT_FOUND,
            )

    def delete(self, request, *args, **kwargs):
        group_id = kwargs.get("pk")
        if group_id:
            group = get_object_or_404(Group, pk=group_id)
            permissions = group.permissions.all()
            permissions = [permission.name for permission in permissions]
            group.delete()
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": f"Group with ID {group_id} deleted successfully along with permissions: {permissions}",
                    "data": {},
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Provide the Role  ID",
                    "data": {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class TargetAPIView(APIView):
    """
    A view to handle CRUD operations for Target instances.

    Supported HTTP Methods:
    - GET: Retrieve all Target instances or a specific Target instance by ID.
    - POST: Create a new Target instance.
    - PUT: Update a specific Target instance.
    - DELETE: Mark a specific Target instance as deleted.
    """

    def get(self, request, pk=None):
        if pk:
            target = get_object_or_404(Target, pk=pk, deleted=False)
            serializer = TargetSerializer(target)
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "Target retrieved by Target ID",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        else:
            targets = Target.objects.filter(deleted=False)
            serializer = TargetSerializer(targets, many=True)
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "Targets retrieved",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

    def post(self, request):
        serializer = TargetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "code": status.HTTP_201_CREATED,
                    "type": "success",
                    "message": "Target is Successfully Created",
                    "data": [serializer.data],
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "error",
                "message": serializer.errors,
                "data": [],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    def put(self, request, pk):
        target = get_object_or_404(Target, pk=pk, deleted=False)
        serializer = TargetSerializer(target, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "Target successfully updated",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "error",
                "message": serializer.errors,
                "data": [],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    def delete(self, request, pk):
        target = get_object_or_404(Target, pk=pk, deleted=False)
        target.deleted = True
        target.deleted_at = timezone.now()
        target.save()
        return Response(
            {
                "code": status.HTTP_200_OK,
                "type": "success",
                "message": "Target with ID {} has been deleted.".format(pk),
            },
            status=status.HTTP_200_OK,
        )


@csrf_exempt
def invite_user(request):
    """
    Handle invitation of a user via email.

    This function validates and processes POST requests to send invitation emails to users.

    Args:
    - request: The HTTP request object.

    Returns:
    - JsonResponse: A JSON response indicating the success or failure of the invitation process.
    """
    if request.method == "POST":
        data = request.POST
        email = data.get("email")
        if email:
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({"error": "Invalid email address"}, status=400)

            invite_code = "".join(
                random.choices(string.ascii_letters + string.digits, k=8)
            )
            send_invitation_email(email, invite_code)
            validity_timestamp = timezone.now() + timedelta(minutes=5)
            return JsonResponse(
                {
                    "message": "Invitation sent successfully",
                    "invite_code": invite_code,
                    "validity_timestamp": validity_timestamp,
                }
            )
        else:
            return JsonResponse({"error": "Email address not provided"}, status=400)
    else:
        return JsonResponse({"error": "Only POST requests are allowed"}, status=405)


def send_invitation_email(email, invite_code):
    """
    Send an invitation email to the specified email address.

    Args:
    - email (str): The recipient's email address.
    - invite_code (str): The invitation code to include in the email.

    Returns:
    - None
    """
    subject = "Invitation to join our platform"
    message = f"Hi,\n\nYou have been invited to join our platform. Your invitation code is: {invite_code}"
    send_mail(subject, message, "your_email@example.com", [email], fail_silently=False)


@api_view(["GET"])
def view_risks(request, pk):
    """
    Retrieve risks associated with a specific project.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the project.

    Returns:
    - Response: A JSON response containing either serialized data of the risks
      associated with the project or a message indicating no risks found.

    """
    try:
        project = Project.objects.get(pk=pk)
    except Project.DoesNotExist:
        return Response(
            {"message": "Project not found."}, status=status.HTTP_404_NOT_FOUND
        )
    risks = Risk.objects.filter(project=project)
    if risks.exists():
        serializer = RiskSerializer(risks, many=True)
        return Response(
            {
                "code": status.HTTP_200_OK,
                "type": "error",
                "message": "isks found for this project.",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    else:
        return Response(
            {
                "code": status.HTTP_404_NOT_FOUND,
                "type": "error",
                "message": "No risks found for this project.",
                "data": "",
            },
            status=status.HTTP_404_NOT_FOUND,
        )


@api_view(["GET"])
def export_vulnerabilities_csv(request, pk):
    """
    Export vulnerabilities associated with a specific project to CSV format.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the project.

    Returns:
    - HttpResponse: A CSV file attachment containing serialized data of the vulnerabilities
      associated with the project.

    """

    if pk:
        try:
            project = Project.objects.get(pk=pk)
            vulnerabilities = project.vulnerabilities.all()
            serializer = VulnerabilitySerializer(vulnerabilities, many=True)
            filetype = request.GET.get("filetype")
            file_path = "addresses.csv"
            try:
                with default_storage.open(file_path, "rb") as file:
                    file_contents = file.read()
            except FileNotFoundError:
                return HttpResponse("File not found.", status=404)

            response = HttpResponse(file_contents, content_type="text/csv")
            response["Content-Disposition"] = (
                f'attachment; filename="{smart_str(file_path)}"'
            )
            return response
        except Project.DoesNotExist:
            return Response(
                {"code": "error", "message": "Project not found. by this project id"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    else:
        return Response(
            {"error": "Provide the Project ID"}, status=status.HTTP_404_NOT_FOUND
        )


@api_view(["GET"])
def download_project_report(request, pk):
    """
    Download a project report in PDF format.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the project.

    Returns:
    - HttpResponse: A PDF file attachment containing serialized data of the project.

    """
    try:
        project = Project.objects.get(pk=pk)
    except Project.DoesNotExist:
        return Response(
            {"message": "Project not found"}, status=status.HTTP_404_NOT_FOUND
        )

    serializer = ProjectSerializer(project)
    file_path = "TEMP-PDF-Document.pdf"
    try:
        with default_storage.open(file_path, "rb") as file:
            file_contents = file.read()
    except FileNotFoundError:
        return HttpResponse("File not found.", status=404)
    response = HttpResponse(file_contents, content_type="tpplication/pdf")
    response["Content-Disposition"] = f'attachment; filename="project_{pk}_report.pdf"'
    return response


@api_view(["PATCH"])
def update_retest_status(request, pk):
    """
    Update the retest status of a project.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the project.

    Returns:
    - Response: A JSON response indicating the success or failure of updating the retest status.

    """
    try:
        project = Project.objects.get(pk=pk)
        pass
    except Project.DoesNotExist:
        return Response(
            {
                "code": status.HTTP_404_NOT_FOUND,
                "type": "success",
                "message": "Project not found",
                "data": "",
            },
            status=status.HTTP_404_NOT_FOUND,
        )
    project.retest = True
    project.save()
    return Response(
        {
            "code": status.HTTP_200_OK,
            "type": "success",
            "message": "No risks found for this project.",
            "data": "",
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET", "POST"])
def scan_list(request):
    """
    Handle GET and POST requests for a list of scans.

    - GET Request:
        Retrieve a list of serialized scans.

    - POST Request:
        Create a new scan using provided data.

    """
    if request.method == "GET":
        scans = Scan.objects.filter(is_deleted=False)
        serializer = ScanSerializer(scans, many=True)
        return Response(
            {
                "code": status.HTTP_200_OK,
                "type": "success",
                "message": "all scan retrived successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    elif request.method == "POST":
        serializer = ScanSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Scan created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "error",
                "message": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class ScanDetail(APIView):
    """
    A view to handle CRUD operations for individual scans.

    Methods:
    - get_object: Retrieves a Scan instance by its primary key.
    - get: Handles HTTP GET requests to retrieve a specific scan.
    - put: Handles HTTP PUT requests to update a specific scan.
    - patch: Handles HTTP PATCH requests to partially update a specific scan.
    - delete: Handles HTTP DELETE requests to mark a specific scan as deleted.
    """

    def get_object(self, pk):
        try:
            scan = Scan.objects.get(pk=pk)
            if scan.is_deleted:
                raise Http404
            return scan
        except Scan.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        try:
            scan = self.get_object(pk)
            serializer = ScanSerializer(scan)
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "scan data get successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        except Http404:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "Scan ID not found",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    def put(self, request, pk):
        scan = self.get_object(pk)
        serializer = ScanSerializer(scan, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "scan data Updated succesfully",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "error",
                "message": serializer.data,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    def patch(self, request, pk):
        scan = self.get_object(pk)
        serializer = ScanSerializer(scan, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "Updated succesfully",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            {
                "code": status.HTTP_200_OK,
                "type": "success",
                "message": serializer.errors,
            },
            status=status.HTTP_200_OK,
        )

    def delete(self, request, pk):
        scan = self.get_object(pk)
        scan.is_deleted = True
        scan.save()
        return Response(
            {
                "code": status.HTTP_200_OK,
                "type": "success",
                "message": "Scan with ID {} has been deleted.".format(pk),
            },
            status=status.HTTP_200_OK,
        )


class PermissionRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

    def post(self, request, *args, **kwargs):
        permissionname = request.data.get("name")
        codename = request.data.get("codename")
        model_name = request.data.get("model")
        try:
            content_type = ContentType.objects.get(model=model_name)
            permission, created = Permission.objects.get_or_create(
                content_type=content_type, codename=codename, name=permissionname
            )
            if created:
                return Response(
                    {
                        "code": status.HTTP_201_CREATED,
                        "type": "success",
                        "message": "Permission Successfully Created",
                        "data": "",
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "type": "error",
                        "message": "Permission  already exists. by name",
                        "data": "",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except ContentType.DoesNotExist:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": "invaid table",
                    "data": "",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    def get(self, request, *args, **kwargs):
        permissionid = kwargs.get("pk")
        if permissionid:
            try:
                group = get_object_or_404(Permission, pk=permissionid)
                serializer = PermissionSerializer(group)
                return Response(
                    {
                        "code": status.HTTP_200_OK,
                        "type": "success",
                        "success": "Permission retrieved successfully",
                        "data": [serializer.data],
                    },
                    status=status.HTTP_200_OK,
                )
            except Permission.DoesNotExist:
                return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "type": "error",
                        "message": serializer.errors,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            try:
                permissions = Permission.objects.all()
                serializer = PermissionSerializer(permissions, many=True)
                return Response(
                    {
                        "code": status.HTTP_200_OK,
                        "type": "success",
                        "success": "All Permission  retrieved successfully",
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            except Exception as e:
                return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "type": "error",
                        "message": str(e),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

    def put(self, request, *args, **kwargs):
        permission_id = kwargs.get("pk")
        permission_instance = get_object_or_404(Permission, pk=permission_id)
        serializer = self.get_serializer(permission_instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {
                "code": status.HTTP_200_OK,
                "type": "success",
                "success": "Permission updated  successfully",
                "data": [serializer.data],
            },
            status=status.HTTP_200_OK,
        )

    def delete(self, request, *args, **kwargs):
        permission_id = kwargs.get("pk")
        permission_instance = get_object_or_404(Permission, pk=permission_id)
        permission_instance.delete()
        return Response(
            {
                "code": status.HTTP_200_OK,
                "type": "success",
                "success": "Permission deleted successfully.",
                "data": [],
            },
            status=status.HTTP_200_OK,
        )


class ProjectList(APIView):
    """
    API endpoint for listing all projects or creating a new project.
    """

    def get(self, request, format=None):
        projects = Project.objects.filter(is_deleted=False)
        serializer = ProjectSerializer(projects, many=True)
        return Response(
            {
                "code": status.HTTP_200_OK,
                "type": "success",
                "message": "Projects received successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request, format=None):
        serializer = ProjectSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "code": status.HTTP_201_CREATED,
                    "type": "success",
                    "message": "Project created successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {
                "code": status.HTTP_400_BAD_REQUEST,
                "type": "success",
                "message": "Project created successfully",
                "data": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class ProjectDetail(APIView):
    """
    API endpoint for retrieving, updating, or deleting a specific project instance.
    """

    def get_object(self, pk):
        try:
            project = Project.objects.get(pk=pk)
            if project.is_deleted:
                raise Http404
            return project
        except Project.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        try:
            project = self.get_object(pk)
            serializer = ProjectSerializer(project)
            return Response(
                {
                    "code": status.HTTP_200_OK,
                    "type": "success",
                    "message": "Project data retrieved successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        except Http404:
            return Response(
                {
                    "code": status.HTTP_404_NOT_FOUND,
                    "type": "error",
                    "message": "Project ID not found",
                    "data": "",
                },
                status=status.HTTP_404_NOT_FOUND,
            )

    def put(self, request, pk, format=None):
        try:
            project = self.get_object(pk)
            serializer = ProjectSerializer(project, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "code": status.HTTP_200_OK,
                        "type": "success",
                        "message": "Project updated successfully",
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "type": "error",
                    "message": serializer.errors,
                    "data": "",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Project.DoesNotExist:
            return Response(
                {
                    "code": status.HTTP_404_NOT_FOUND,
                    "type": "error",
                    "message": "projects is not foud",
                    "data": "",
                },
                status=status.HTTP_404_NOT_FOUND,
            )

    def delete(self, request, pk, format=None):
        project = self.get_object(pk)
        project.is_deleted = True
        project.save()
        return Response(
            {
                "code": status.HTTP_204_NO_CONTENT,
                "type": "error",
                "message": "Deleted successfully",
                "data": "",
            },
            status=status.HTTP_204_NO_CONTENT,
        )


class RisksListCreateAPIView(APIView):
    """
    API endpoint for listing all risks or creating a new risk.
    """

    def get(self, request):
        risks = Risks.objects.all()
        serializer = RisksSerializer(risks, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = RisksSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Risk created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RisksRetrieveUpdateDestroyAPIView(APIView):
    """
    API endpoint for retrieving, updating, or deleting a specific risk instance.
    """

    def get_object(self, pk):
        try:
            risk = Risks.objects.get(pk=pk)
            if risk.is_deleted:
                raise Http404
            return risk
        except Risks.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        risk = self.get_object(pk)
        serializer = RisksSerializer(risk)
        return Response(serializer.data)

    def put(self, request, pk):
        risk = self.get_object(pk)
        serializer = RisksSerializer(risk, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        risk = self.get_object(pk)
        risk.is_deleted = True
        risk.save()
        return Response(
            {"message": "Deleted successfully"}, status=status.HTTP_204_NO_CONTENT
        )


@api_view(["GET"])
def download_scan_report(request, pk):
    try:
        scan = Scan.objects.get(pk=pk)
    except Scan.DoesNotExist:
        return Response({"message": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

    file_path = f"scan_{pk}_report.pdf"

    if not default_storage.exists(file_path):
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        p.drawString(100, 750, f"Scan ID: {scan.pk}")
        p.drawString(100, 730, f"Scan Engines: {scan.scan_engines}")
        p.drawString(100, 710, f"Scan Schedule: {scan.scan_schedule}")
        p.drawString(100, 690, f"Start Time: {scan.start_time}")
        p.save()

        # Save PDF file to default storage
        default_storage.save(file_path, ContentFile(buffer.getvalue()))

    try:
        # Retrieve PDF file contents from default storage
        with default_storage.open(file_path, "rb") as file:
            file_contents = file.read()
    except FileNotFoundError:
        return HttpResponse("File not found.", status=404)

    # Create HTTP response with PDF file attachment
    response = HttpResponse(file_contents, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{file_path}"'

    return response


class DownloadOutputCSVAPIView(APIView):
    """
    API endpoint to download output data of a scan in CSV format.

    Parameters:
        scan_id (int): The ID of the scan for which to download the output CSV.

    Returns:
        HttpResponse: The CSV file containing the output data of the scan.
    """

    def get(self, request, scan_id):
        try:
            scan = Scan.objects.get(pk=scan_id)
        except Scan.DoesNotExist:
            return Response(
                {"message": "Scan not found"}, status=status.HTTP_404_NOT_FOUND
            )

        scan_data = {
            "Scan ID": scan.pk,
            "Targets": scan.targets.name,
            "Scan Engines": scan.scan_engines,
            "Scan Schedule": scan.get_scan_schedule_display(),
            "Start Time": scan.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "Is Deleted": "Yes" if scan.is_deleted else "No",
        }

        file_path = os.path.join(settings.BASE_DIR, f"scan_{scan_id}_output.csv")

        with open(file_path, "w", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=list(scan_data.keys()))
            writer.writeheader()
            writer.writerow(scan_data)

        with open(file_path, "rb") as csv_file:
            response = HttpResponse(csv_file.read(), content_type="text/csv")
            response["Content-Disposition"] = (
                f'attachment; filename="scan_{scan_id}_output.csv"'
            )

        return response


