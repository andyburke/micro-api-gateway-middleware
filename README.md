# micro-api-gateway-middleware

"Middleware" to help verify [micro-api-gateway](https://www.npmjs.com/package/micro-api-gateway) gateway requests.

## EXAMPLE

```javascript
const is_from_gateway = require( 'micro-api-gateway-middleware' )( {
    // can get the API gateway's public key via an endpoint, or:
    public_key_endpoint: 'https://your.gateway.com/public.pem',

    // you could just specify the public key to trust
    public_key: '<public key>',

    // you can specify headers to verify in the request signature
    headers_to_verify: [
        'x-my-special-header',
        'x-some-other-header'
    ]
} );

// ... later, in your request handler:
async function handle_request( request, response ) {
    if ( !await is_from_gateway( request, response ) ) {
        return; // just return, is_from_gateway will have sent them a response if it fails
    }

    // ...
}
```

## BYPASSING

If you'd like to bypass the gateway check, for instance, while you're testing
or developing on your local machine. You can set the
```SKIP_GATEWAY_VERIFICATION``` environment variable to a truthy value and
all checks against the gateway will succeed.