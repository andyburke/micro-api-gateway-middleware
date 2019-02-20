'use strict';

const crypto = require( 'crypto' );
const extend = require( 'extend' );
const fetch = require( 'node-fetch' );
const httpstatuses = require( 'httpstatuses' );
const json_stable_stringify = require( 'json-stable-stringify' );

module.exports = function( _options ) {
    const options = Object.assign( {
        headers: {
            time: 'x-micro-api-gateway-signature-time',
            hash: 'x-micro-api-gateway-request-hash',
            signature: 'x-micro-api-gateway-signature'
        },
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
            const public_key_request = await fetch( options.public_key_endpoint );
            if ( !public_key_request.ok ) {
                fetched_public_key = null;
                return fetched_public_key;
            }
    
            fetched_public_key = await public_key_request.text();
            last_public_key_update = now;
        }

        return fetched_public_key;
    }

    return async ( request, response ) => {

        const public_key = await get_public_key();

        if ( !public_key ) {
            response.statusCode = httpstatuses.internal_server_error;
            response.setHeader( 'Content-Type', 'application/json' );
            response.end( JSON.stringify( {
                error: 'missing public key',
                message: `Could not obtain public key from provided endpoint.`
            } ) );
            return false;
        }

        const headers_to_verify = extend( true, {}, request.headers );
        delete headers_to_verify[ options.headers.hash ];
        delete headers_to_verify[ options.headers.signature ];
        delete headers_to_verify[ 'connection' ];
        delete headers_to_verify[ 'transfer-encoding' ];

        const request_as_string = [ request.method, request.url, json_stable_stringify( headers_to_verify ) ].join( ':::' );
        const request_hash = crypto.createHash( 'SHA256' ).update( request_as_string ).digest( 'base64' );

        const now = +new Date();
        const time_delta = now - parseInt( request.headers[ options.headers.time ] );
        if ( time_delta > options.grace_period ) {
            response.statusCode = httpstatuses.bad_request;
            response.setHeader( 'Content-Type', 'application/json' );
            response.end( JSON.stringify( {
                error: 'expired request',
                message: 'The request from the API gateway has expired.'
            } ) );
            return false;
        }

        if ( request_hash !== request.headers[ options.headers.hash ] ) {
            response.statusCode = httpstatuses.bad_request;
            response.setHeader( 'Content-Type', 'application/json' );
            response.end( JSON.stringify( {
                error: 'invalid request hash',
                message: 'The request from the API gateway has an invalid request hash.'
            } ) );
            return false;
        }

        const request_hash_verified = crypto.createVerify( 'RSA-SHA256' ).update( request_hash ).verify( public_key, request.headers[ options.headers.signature ], 'base64' );

        if ( !request_hash_verified ) {
            response.statusCode = httpstatuses.bad_request;
            response.setHeader( 'Content-Type', 'application/json' );
            response.end( JSON.stringify( {
                error: 'invalid request hash signature',
                message: 'The request hash from the API gateway could not be verified.'
            } ) );
            return false;
        }

        return true;
    };
};