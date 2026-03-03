# Hi Keepsafe!
## Welcome to my demo 🧑‍🏫


### 🚀 Features
Passwordless Auth: No passwords needed; log in via 4-digit codes sent to your terminal (for demo purposes).

🚀 Secure Sessions: Uses secrets module to generate Bearer tokens.
🚀 Rate Limiting: Protects endpoints from abuse using Flask-Limiter.
🚀 Protection: Automatically locks out emails after 3 failed attempts within 15 minutes.
🚀 Isolated Storage: Files are stored in user-specific directories


### 🛠️ Setup
Copy and paste this to open docker and build container.
```
open -a docker
```
```
docker-compose up
```

### :stars: Endpoints
```
POST http://0.0.0.0:8000/sign-up

POST http://0.0.0.0:8000/auth/code/request

POST http://0.0.0.0:8000/auth/code/verify

POST http://0.0.0.0:8000/sign-out

GET  http://0.0.0.0:8000/file/<file_name>

POST http://0.0.0.0:8000/file/<file_name>
```

### Customize your security features

  __CODE_EXPIRY_SECONDS:__ How long a login code remains valid - default at 5 minutes
  
 __SESSION_EXPIRY_SECONDS:__ Length of user session before re-auth is required - default at 30 minutes.

  __MAX_FAILED_ATTEMPTS:__ Number of wrong codes allowed before lockout - default at 3 attempts.
  
  __LOCKOUT_WINDOW_SECONDS:__ Duration of the login ban - default at 15 minutes.

### Steps
1) Set up Docker container
2)  Create an acccount with an email and a device ID string. If you already have an account set up, skip this step.
 ```
curl -X POST http://localhost:8000/sign-up \
  -d "email=example@example.com"
 ```
3) Log in by requesting a verification code. You should recieve a code in this format: ```{"code":"0000","message":"code sent"}``` 
  ```
  curl -X POST http://localhost:8000/auth/code/request \
  -d "email=example@example.com&device_id=my-phone"
  ```
4) Using that provided 4-digit code, verify your account.
```
curl -X POST http://localhost:8000/auth/code/verify \
  -d "code=0000&device_id=my-phone&email=example@example.com"
```
5) To upload a file first make sure you have your desired file in the uploads/ folder. I have some pre-made example files there already.
