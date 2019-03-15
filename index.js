'use strict';

const crypto = require( 'crypto' );
const fetch = require( 'node-fetch' );
const httpstatuses = require( 'httpstatuses' );
const json_stable_stringify = require( 'json-stable-stringify' );

module.exports = function( _options ) {

    if ( process.env.SKIP_GATEWAY_VERIFICATION ) {
        console.warn( '!!! API GATEWAY VERIFICATION WILL BE SKIPPED (SKIP_GATEWAY_VERIFICATION SET IN ENV) !!!' );
    }

    const options = Object.assign( {
        headers: {
            time: 'x-micro-api-gateway-signature-time',
            hash: 'x-micro-api-gateway-request-hash',
            signature: 'x-micro-api-gateway-signature'
        },
        headers_to_verify: [],
        public_key_endpoint: null,
        public_key: null,
        grace_period: 1000 * 60 * 5 // 5 minutes of grace on signature time
    }, _options );

    if ( !( options.public_key_endpoint || options.public_key ) ) {
        throw new Error( 'You must specify a public key or public key endpoint!')
    }

    let fetched_public_key = null;
    let last_public_key_update = 0;
    async function get_public_key() {
        if ( options.public_key ) {
            return options.public_key;
        }

        const now = +new Date();
        const time_since_last_public_key_update = now - last_public_key_update;

        if ( !fetched_public_key || time_since_last_public_key_update > options.grace_period ) {
            fetched_public_key = null;

            try {
                const public_key_request = await fetch( options.public_key_endpoint );
                fetched_public_key = public_key_request.ok ? await public_key_request.text() : null;

                if ( !public_key_request.ok ) {
                    console.warn( `Failed to fetch api gateway public key. (HTTP response code: ${ public_key_request.status })` );
                }
            }
            catch( ex ) {
                fetched_public_key = null;
                console.warn( ex && ex.message ? ex.message : ex );
            }
    
            if ( fetched_public_key ) {
                last_public_key_update = now;
            }
        }

        return fetched_public_key;
    }

    return async ( request, response ) => {

        // if SKIP_GATEWAY_VERIFICATION is set, just return true
        // this should be used for internal testing only
        if ( process.env.SKIP_GATEWAY_VERIFICATION ) {
            return true;
        }

        const public_key = await get_public_key();

        if ( !public_key ) {
            response.statusCode = httpstatuses.internal_server_error;
            response.setHeader( 'content-type', 'application/json' );
            response.end( JSON.stringify( {
                error: 'missing public key',
                message: `Could not obtain public key from provided endpoint.`
            } ) );
            return false;
        }

        const incoming_request_hash = request.headers[ options.headers.hash ];
        if ( typeof incoming_request_hash !== 'string' ) {
            response.statusCode = httpstatuses.bad_request;
            response.setHeader( 'content-type', 'application/json' );
            response.end( JSON.stringify( {
                error: 'missing or malformed request hash',
                message: 'The request does not have a proper request hash header.'
            } ) );
            return false;
        }

        const incoming_request_hash_signature = request.headers[ options.headers.signature ];
        if ( typeof incoming_request_hash_signature !== 'string' ) {
            response.statusCode = httpstatuses.bad_request;
            response.setHeader( 'content-type', 'application/json' );
            response.end( JSON.stringify( {
                error: 'missing or malformed request hash signature',
                message: 'The request does not have a proper request hash signature header.'
            } ) );
            return false;
        }

        const headers_to_verify = options.headers_to_verify.reduce( ( _headers_to_verify, header ) => {
            if ( typeof request.headers[ header ] !== 'undefined' ) {
                _headers_to_verify[ header ] = request.headers[ header ];
            }
            return _headers_to_verify;
        }, {} );

        const request_as_string = [ request.method, request.url, json_stable_stringify( headers_to_verify ) ].join( ':::' );
        const request_hash = crypto.createHash( 'SHA256' ).update( request_as_string ).digest( 'base64' );

        if ( process.env.API_GATEWAY_MIDDLEWARE_DEBUG ) {
            console.log( `VERIFY REQ: ${ request_as_string }` );
            console.log( `VERIFY HASH: ${ request_hash }` );
        }

        const now = +new Date();
        const time_delta = now - parseInt( request.headers[ options.headers.time ] );
        if ( time_delta > options.grace_period ) {
            response.statusCode = httpstatuses.bad_request;
            response.setHeader( 'content-type', 'application/json' );
            response.end( JSON.stringify( {
                error: 'expired request',
                message: 'The request from the API gateway has expired.'
            } ) );
            return false;
        }

        if ( request_hash !== incoming_request_hash ) {
            response.statusCode = httpstatuses.bad_request;
            response.setHeader( 'content-type', 'application/json' );
            response.end( JSON.stringify( {
                error: 'invalid request hash',
                message: 'The request from the API gateway has an invalid request hash.'
            } ) );
            return false;
        }

        const request_hash_verified = crypto.createVerify( 'RSA-SHA256' ).update( request_hash ).verify( public_key, incoming_request_hash_signature, 'base64' );

        if ( !request_hash_verified ) {
            response.statusCode = httpstatuses.bad_request;
            response.setHeader( 'content-type', 'application/json' );
            response.end( JSON.stringify( {
                error: 'invalid request hash signature',
                message: 'The request hash from the API gateway could not be verified.'
            } ) );
            return false;
        }

        return true;
    };
};