# How to use MVD

## Main app: MVD Console

http://localhost:7651

On the "Public Key registry" screen, you have to register users:

1. Enter a UserID and click "Generate User"
2. Below, create a public key with the "Register" button

Below, you will see the generated local keys.

On the "Federated Catalog" screen, you can enter assets.

- For an API, use field "Endpoint" and enter the URL.
- For offering files, there are files (at least one) you can offer in the fileserver. Use Resource Path "http://host.docker.internal:7552/hello_world.txt"

On the "Authorization" screen, you can create offers. 

- Enter which user offers what resource to which other user. 
- You must also enter an expiration date in format `2099-12-31T23:59:59`.

On the "Invoke Resource" screen, you can get the offered resources.

- enter the user who wants to get the resource
- enter the Resource ID
- enter the method (e.g. GET or POST)
- if necessary, enter also query parameters
- if necessary, enter also headers
- select the Authorization type and enter the credentials, if necessary
- for POST requests, you may also enter a body

  
## Federated Catalog & Public Key Registry

http://localhost:7650/

On the "Federated Catalog" screen, you see the resources and can search/filter them.

On the "Public Key Registry" screen, you can search for public keys (enter an id).