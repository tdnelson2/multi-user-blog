# Multi User Blog
The purpose of this project is to demonstrate how you can used Google App Engine to build a full featured blog. It also demostrates how to implement some social media features such as the ability to comment on and like posts.
## URL
* Working version of this site can be viewed at [https://hello-world-165416.appspot.com/bogspot](https://hello-world-165416.appspot.com/bogspot)
## Installation
* [Install Google App Engine](https://drive.google.com/open?id=0Byu3UemwRffDc21qd3duLW9LMm8)
* Clone this project to your system
* In terminal cd into the project folder and run `dev_appserver.py ./`
* In a web browser go to `http:\\localhost\8080\bogspot` and you should see the main page.
## Deploy
* Setup a Google Cloud account and [create a new project](https://console.cloud.google.com/start)
* Click on the `Select a project` drop down and `Create Project` plus sign `+` and name it 'hello-world'
* Wait 30 seconds or so
* Run `gcloud app deploy`
* Go to the url that gets provided after you run the aforementioned command
## Features
* Login generates a secure cookie uniquely identifying the user
* Passwords are hashed and salted for added security
* Static links render dynamically and display contextual information
## Future Improvements
* Return user to origin after they get bounced to the sign in page
* Return user to orgin after they like/comment/edit/delete
* Support markdown