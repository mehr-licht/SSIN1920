# SSIN1920

```npm i```

``` sh run.sh```

in the client view (localhost:9000)\
* click on ```Get OAuth Token```
* approve the scopes and authorizations suggested
once redirected:
* click on ```Get Protected Resource```

you can check the other views during the whole process:
```localhost:9001``` and ```localhost:9002```


<hr>
what ```run.sh``` does

```node client.js```\
OAuth Client is listening at http://127.0.0.1:9000


```node authorizationServer.js```\
OAuth Authorization Server is listening at http://127.0.0.1:9001


```node protectedResource.js```\
OAuth Resource Server is listening at http://127.0.0.1:9002

