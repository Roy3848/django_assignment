
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
import random
from django.contrib.auth import authenticate,login,logout
from rest_framework.response import Response
from API import serializer as s
from API.models import EmployeeUser
from rest_framework.generics import CreateAPIView,RetrieveAPIView,UpdateAPIView
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework import status
from API.serializer import EmployeeSerializer, EmployeeLoginSerializer, EmployeeProfileSerializer,SuperUserSerializer
from django.core.mail import send_mail

# create Manually token Here 
def createToken(user):

    userToken = RefreshToken.for_user(user=user)

    token = {
        'access': str(userToken.access_token),
        'refresh': str(userToken)
    }

    return token

# randam password generated here
def CreateRandomPassword():
    string = 'abcdefghijklmnopqrstwxyz'
    upperString = string.upper()
    digit = '1234567890'
    special_Character = '@#$&?*^'
    combine = string+upperString+digit+special_Character
    password = "".join(random.sample(combine, 8))
    return password

# checking valid token here 
def CheckingTokenValid(token):
    try:
        userToken = RefreshToken(token)
        userToken.check_blacklist()
        return True
    except BaseException as e:
        return False

# register employee user here, employee create only by manager
class CreateAPI(CreateAPIView):

    authentication_classes = [BasicAuthentication,JWTAuthentication ]
    permission_classes = [IsAuthenticated]
    queryset = EmployeeUser
    serializer_class = EmployeeSerializer

    # send mail here with email and password to the employee email
    def send_mail(self,email,password):
        send_mail(
            'About Credntial',
            f'''Email :- {email} 
             password {password}''',
            'rohit.ghule@mindbowser.com',
            [email],
            fail_silently=False,
        )

    def post(self, request):
        user_manager = EmployeeUser.objects.get(email=request.user)
        manager_serializer = s.CheckManagerSerializer(user_manager)
        is_manager = manager_serializer.data['is_manager']
        if is_manager:
            user_data = request.data
            serializer = EmployeeSerializer(data=user_data)
            if serializer.is_valid(raise_exception=True):
                email = request.data.get('email')
                serializer.save()
                user = EmployeeUser.objects.get(email=email)
                password = CreateRandomPassword()
                user.set_password(password)
                tokenn = createToken(user)
                user.save()
                self.send_mail(email,password)
                return Response({"status": "success", "token": tokenn}, status=status.HTTP_200_OK)
            else:
                return Response({"status": "Failed"}, status=status.HTTP_406_NOT_ACCEPTABLE)
        else:
            return Response({"status":"failed","message":"Your Not Manager So You Have Not Rights To Register Emplyoee"})

# login user here
class UserLogin(CreateAPIView):

    serializer_class = EmployeeLoginSerializer
    queryset = EmployeeUser
    authentication_classes = [JWTAuthentication,]
    def user_object(self,user):
        user_obj = EmployeeUser.objects.get(email=user)
        return user_obj

    def user_profile(self,user):
        profile_serializer = EmployeeProfileSerializer(user)
        return profile_serializer.data

    def post(self, request):
        serializer = EmployeeLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(request,email=email, password=password)
            if user is not None:
                login(request,user)
                user_obj = self.user_object(email)
                user_profile = self.user_profile(user_obj)
                user_token = createToken(user_obj)

                return Response({'status': 'login successfully','profile':user_profile,'token':user_token}, status=status.HTTP_200_OK)
            else:
                return Response({'status': 'login Failed'}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'status': 'login Failed'}, status=status.HTTP_406_NOT_ACCEPTABLE)

# logout here
class UserLogout(RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [BasicAuthentication,JWTAuthentication]
    serializer_class = EmployeeProfileSerializer
    queryset = EmployeeUser
    def get(self,request):
        user_profile = EmployeeProfileSerializer(request.user)
        token = RefreshToken(request.data.get('refresh'))
        accessToken = RefreshToken(request.data.get('access'))
        token.blacklist()
        accessToken.blacklist()
        logout(request)
        return Response({"status":"Logged Out!","User":user_profile.data['email']})

# user can access their profile here 
class UserProfile(RetrieveAPIView):

    authentication_classes = [BasicAuthentication,JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = EmployeeProfileSerializer(request.user)
        return Response({"status":"success","profile":serializer.data})

# create super user here, it check if super user is already there or not if not then create else wont create
class CreateSuperUser(CreateAPIView):
    serializer_class = SuperUserSerializer

    def setPassword(self,user,password):
        user_obj = EmployeeUser.objects.get(email=user)
        user_obj.set_password(password)
        user_obj.save()
        return

    def post(self, request):
        try:
            super_user = EmployeeUser.objects.get(is_admin=True)
            return Response({"status":"Failed Super is Already There"},status=status.HTTP_406_NOT_ACCEPTABLE)

        except BaseException as e:
            print("error",e)

            serializer = SuperUserSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                email = request.data['email']
                password = request.data['password']
                print(request.data['password'])
                serializer.save()
                self.setPassword(email,password)
                return Response({"status":"success","Admin":"created"})

# create manager user here, it check if manager user is already there or not if not then create else wont create manager can create only by admin user
class CreateManager(CreateSuperUser,CreateAPIView):
    serializer_class = s.ManagerSerialzer
    permission_classes = [IsAdminUser]
    authentication_classes = [BasicAuthentication]

    def post(self, request):
        try:
            manger_user = EmployeeUser.objects.get(is_manager=True)
            return Response({"status":"Failed Manager User Is Already There"},status=status.HTTP_406_NOT_ACCEPTABLE)

        except BaseException:
            serializer = s.ManagerSerialzer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                email = request.data['email']
                password = request.data['password']
                print(request.data['password'])
                serializer.save()
                self.setPassword(email,password)
                return Response({"status":"success","Admin":"created"})

# change user password here
class ChangePassword(UpdateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [BasicAuthentication,JWTAuthentication]
    serializer_class = s.UserChangePassword
    queryset = EmployeeUser.objects.all()
    lookup_field = "pk"

    def update(self, request):
        if str(request.data['email'])==str(request.user):
            userEmail = request.data['email']
            userObj = EmployeeUser.objects.get(email=userEmail)
            serializers = s.UserChangePassword(userObj,data=request.data,partial=True)
            if serializers.is_valid(raise_exception=True):
                serializers.save()
                return Response({"status":"success","email":userEmail,"message":"Your Password Changed Successfully"},status=status.HTTP_200_OK)
            else:
                return Response({"status":"failed","message":"filled data is Not Valid!"},status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"status":"failed","message":"Your Not Login Here"},status=status.HTTP_400_BAD_REQUEST)

# forgot password it can access by only manager
class ForgotPassword(UpdateAPIView):
    serializer_class = s.UserForgetPassword
    queryset = EmployeeUser
    permission_classes = [IsAuthenticated]

    def send_mail(self,email,password):
        send_mail(
            'About Credntial',
            f'''Email :- {email} 
             password {password}''',
            'rohit.ghule@mindbowser.com',
            [email],
            fail_silently=False,
        )

    def update(self, request):
        manager_obj = EmployeeUser.objects.get(email=request.user)
        if(manager_obj.is_manager):
            try:
                userObj = EmployeeUser.objects.get(email=request.data['email'])
                password = CreateRandomPassword()
                userObj.set_password(password)
                userObj.save()
                self.send_mail(request.data['email'],password)
                return Response({"status":"success","Message":"Password Reset Successfully, sends password in register email id"},status=status.HTTP_201_CREATED)
            except BaseException as e:
                print("error",e)
                return Response({"status":"failed","message":"Enter Email is Not Correct!"},status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"status":"failed","message":"Your Are Not Manger Cant Access This API"},status=status.HTTP_403_FORBIDDEN)

# any user can access this api and generate forgot password request on register mail they got link about change password link

class ForgotPasswordUserRequest(CreateAPIView):
    serializer_class = s.UserForgetPassword
    queryset = EmployeeUser

    def send_mail(self,email,link):
        message = f'http://127.0.0.1:8000/api/cngPass/ "Authorization: Bearer {link}"'
        send_mail(
            'Below there is password change link',
            f'{message}',
            'rohit.ghule@mindbowser.com',
            [email],
            fail_silently=False,
        )
    def post(self, request):
        try:
            userObj = EmployeeUser.objects.get(email=request.data['email'])
            token = createToken(userObj)
            link = str(token.get('access'))
            self.send_mail((request.data['email']),link)
            return Response({"status":"success"})
        except BaseException as e:
            print("error",e)
            return Response({"status":"failed"})
