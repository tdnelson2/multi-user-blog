# Multi User Blog
The purpose of this project is to demonstrate how you can used Google App Engine to build a full featured blog. It also demostrates how to implement some social features such as the ability to comment on and like posts.
## Installation
* Install Google App Engine
* Clone this project to your system
* In terminal cd into the project folder and run `dev_appserver.py ./`
* In a web browser go to `http:\\localhost\8080\bogspot` and you should see the main page.
## Deploy
* Setup a Google Cloud account and create a new project
* In terminal go to the project folder and run [command that links to gcloud]
* Run `gcloud app deploy`
* Go to the url that gets provided after you run the aforementioned command
## Features
* Login generates a secure cookie uniquely identifying the user
* Passwords are hashed and salted for added security
* Static links render dynamically and display contextual information