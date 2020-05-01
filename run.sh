#!/bin/sh

cd myapp

gnome-terminal --tab --title="Client" -- bash -c "node client.js; $SHELL"
#OAuth Client is listening at http://127.0.0.1:9000

gnome-terminal --tab --title="AuthServer" -- bash -c "node authorizationServer.js; $SHELL"
#OAuth Authorization Server is listening at http://127.0.0.1:9001

gnome-terminal --tab --title="ProtectedResource" -- bash -c "node protectedResource.js; $SHELL"
#OAuth Resource Server is listening at http://127.0.0.1:9002

npm start
#DEBUG=oAuth2:* npm start

