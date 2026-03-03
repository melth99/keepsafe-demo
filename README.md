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


