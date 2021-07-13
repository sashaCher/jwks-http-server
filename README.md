# Lightweight JWKS server

Lightweight JWKS server for testing purpose

## Usage

### Run

`jwks_server.py [-h] [-p PORT]`

### Request

|Method|Path|Description|
|---|---|---|
|GET|/|Returns JWKS with all keys|
|GET|/key_name/alg|Returns JWKS with one, key_name, key<br>If key_name does not exists key is generated|
|POST|/key_name/alg|Re-signs JWT from body using key_name and alg<br>If key_name does not exists key is generated|
|DELETE|/|Removes all keys|
|DELETE|/key_name/alg|Removes key_name key|

## Supported alg values and key lengths

|JWT alg|Encryption alg|Key length|
|---|---|---|
|RS256|RSA|1024|
|RS384|RSA|2048|
|RS512|RSA|4048|
|ES256|EC|P-256|
|ES384|EC|P-384|
|ES512|EC|P-521|
|HS256|HMAC|256|
|HS384|HMAC|384|
|HS512|HMAC|512|

## Examples

```
$ curl http://localhost:8080/key1/RS256    
{
   "keys":[
      {
         "e":"AQAB",
         "kty":"RSA",
         "n":"vj_nvzzrZ7dQFxeqG2Sho1IjS62ZzhcSxIvQGh-dWeW4WJ4RKwTMXW7c4SBx5GHuMB84_iV5AaMolFTf8Ye35SCeq4fKLx6V6hNpXN7ympvuTCzUd7Jc2oUmifXTV9Nx98s4585i1m946PFoSWol2Yul8EqPUDS36odzfw-ozb8",
         "kid":"WSUMaZUk3CHbOZDLkeAPZedVH-7Z3tuy_WLLXShx_lU"
      }
   ]
}
```
```
$ curl -d "eyJ0eXBlIjoiSldUIiwiYWxnIjoibm9uZSJ9.eyJjbGFpbSI6InZhbHVlIn0." -X POST http://localhost:8080/key2/ES256 
eyJhbGciOiJFUzI1NiIsImtpZCI6IkV5SzJzUE5ZZjJlYS1GOGJwc3NvTVRaTnhoRFFBc1ZPRktMYm01R1d1UW8iLCJ0eXBlIjoiSldUIn0.eyJjbGFpbSI6InZhbHVlIn0.nFFHxjieK97jzKrZcYhK0fVcyWNCIXdwzXDjri9xz3WBGAVLPX-F4EsiU6eIzB3NE2AnEWTc-RPPqN9nOkeWOg
```
```
$ curl http://localhost:8080
{
   "keys":[
      {
         "e":"AQAB",
         "kty":"RSA",
         "n":"vj_nvzzrZ7dQFxeqG2Sho1IjS62ZzhcSxIvQGh-dWeW4WJ4RKwTMXW7c4SBx5GHuMB84_iV5AaMolFTf8Ye35SCeq4fKLx6V6hNpXN7ympvuTCzUd7Jc2oUmifXTV9Nx98s4585i1m946PFoSWol2Yul8EqPUDS36odzfw-ozb8",
         "kid":"WSUMaZUk3CHbOZDLkeAPZedVH-7Z3tuy_WLLXShx_lU"
      },
      {
         "crv":"P-256",
         "kty":"EC",
         "x":"ynOOicHpLZScdycC5jg666t_rUKD49lveItN47TI1kE",
         "y":"v22gshtEw4ilNrnSpXL3hEHsVXkvoam5VBWPqdtsCMg",
         "kid":"EyK2sPNYf2ea-F8bpssoMTZNxhDQAsVOFKLbm5GWuQo"
      }
   ]
}
```
