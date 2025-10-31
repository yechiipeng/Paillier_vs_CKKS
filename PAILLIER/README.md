# Privacy-Preserving Geofencing using Paillier and CKKS Encryption
### Project Owner: 
Tojehova Ajero
### Supervisor:
Dr Hai-Van Dang
### Project Vision

#### How to Run:
Open Docker and VScode. In VScode open project folder then run the command "docker-compose up -d --build". Wait for it to fetch all geofences. 

#### Where to Find Tests:
Runtime and Scalability can be found in main of User.py. The Scalability test cases need to be changed mannually by changing the number of requests, same goes for Runtime test cases however to change this you need to go to Geofencing-Microservice folder and change number of geofences i have commented saying what variable you need to change in app.py.
Accuracy and Security Overhead can be found in main of CircularGeofencing.py.
