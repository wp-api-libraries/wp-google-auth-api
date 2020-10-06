<?php
/**
 * WP Google Auth API
 *
 * @package WP-API-Libraries\WP-Google-Auth-API
 */

/*
* Plugin Name: WP Google Auth API
* Plugin URI: https://github.com/wp-api-libraries/wp-google-auth-api
* Description: Generate access tokens for google service accounts.
* Author: WP API Libraries
* Version: 1.0.0
* Author URI: https://wp-api-libraries.com
* GitHub Plugin URI: https://github.com/wp-api-libraries/wp-google-auth-api
* GitHub Branch: master
*/

/* Exit if accessed directly. */
if (! defined('ABSPATH') ) {
    exit; 
}

/* Check if class exists. */
if (! class_exists('WPGoogleAuth') ) {

    /**
     * WPGoogleAuth Class.
     */
    class WPGoogleAuth
    {
        /**
         * API Key.
         *
         * @var string
         */
        public $access_token;

        /**
         * The type of token returned.
         *
         * @var string
         */
        public $token_type;

        /**
         * Unix timestamp of when the token will expire.
         *
         * @var string
         */
        public $expires_at;
        
        /**
         * Service Account Array
         *
         * @var Array
         */
        private $service_account;

        /**
         * Token access scope to be requested.
         *
         * @access protected
         * @var    string
         */
        private $scope;

        /**
         * Args to be passed into request.
         *
         * @var array
         */
        private $args = array();

        /**
         * Class constructor.
         *
         * @param string $access_token Google API Key.
         */
        public function __construct( $service_account_json, $scope )
        {
            $service_account = $this->is_json_valid($service_account_json);
            if (is_wp_error($service_account)) {
                $this->access_token = $service_account;
                return $this;
            }

            $this->service_account = $service_account;
            
            $response = $this->generate_token($scope);
            if (is_wp_error($response)) {
                $this->access_token = $response;
            }

            return $this;
        }

        /**
         * Prepares API request.
         *
         * @param  string $route  API route to make the call to.
         * @param  array  $args   Arguments to pass into the API call.
         * @param  array  $method HTTP Method to use for request.
         * @return self           Returns an instance of itself so it can be chained to the fetch method.
         */
        protected function build_request( $args = array(), $method = 'GET' )
        {
            // Start building query.
            $this->set_headers();
            $this->args['method'] = $method;
            $this->args['body'] = $args;

            return $this;
        }


        /**
         * Fetch the request from the API.
         *
         * @access private
         * @return array|WP_Error Request results or WP_Error on request failure.
         */
        protected function fetch()
        {
            // Make the request.
            $response = wp_remote_request($this->service_account->token_uri, $this->args);

            // Retrieve Status code & body.
            $code = wp_remote_retrieve_response_code($response);
            $body = json_decode(wp_remote_retrieve_body($response));

            $this->clear();

            // Return WP_Error if request is not successful.
            if (! $this->is_status_ok($code) ) {
                return new WP_Error('response-error', sprintf(__('Status: %d', 'wp-google-auth-api'), $code), $body);
            }

            return $body;
        }


        /**
         * Set request headers.
         */
        protected function set_headers()
        {

            // Set request headers.
            $this->args['headers'] = array(
                'Content-Type'  => 'application/x-www-form-urlencoded',
            );
            
        }

        /**
         * Clear query data.
         */
        protected function clear()
        {
            $this->args = array();
        }

        /**
         * Check if HTTP status code is a success.
         *
         * @param  int $code HTTP status code.
         * @return boolean       True if status is within valid range.
         */
        protected function is_status_ok( $code )
        {
            return ( 200 <= $code && 300 > $code );
        }

        /**
         * Undocumented function
         *
         * @param [type] $service_account_json
         * @return void
         */
        private function is_json_valid($service_account_json)
        {
            $is_valid = true;
            $service_account = json_decode($service_account_json);

            if ( json_last_error() != JSON_ERROR_NONE 
                || ! array_key_exists('private_key', $service_account)
                || ! array_key_exists('client_email', $service_account)
                || ! array_key_exists('token_uri', $service_account)
                || ! array_key_exists('auth_uri', $service_account)
            ) {
                return new WP_Error('invalid-service-account-json', __( "Please verify that a valid service account json string is being used.", "wp-google-auth-api" ));
            }

            return $service_account;
            
        }
        
        /**
         * Generate access token.
         *
         * @param string $scope
         * @return string|WP_Error
         */
        public function generate_token($scope)
        {
            // Unix time of when token was issued.
            $issue_time = time();

            // JWT Header.
            $header = json_encode(['typ' => 'JWT', 'alg' => 'RS256']);
            
            // JWT Payload.
            $payload = json_encode([
                'iss' => $this->service_account->client_email, 
                'scope' => $scope, 
                'aud' => $this->service_account->token_uri, 
                'exp' => $issue_time + (MINUTE_IN_SECONDS * 59), // Set to max amount of time.
                'iat' => $issue_time 
            ]);

            // Encode Header to Base64Url String
            $base64_header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));

            // Encode Payload to Base64Url String
            $base64_payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

            // Create Signature Hash
            openssl_sign($base64_header . "." . $base64_payload, $signature, $this->service_account->private_key, OPENSSL_ALGO_SHA256);
            $base64_signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
            
            $args = 'grant_type=' . urlencode( 'urn:ietf:params:oauth:grant-type:jwt-bearer') . '&assertion=' . $base64_header . "." . $base64_payload . "." . $base64_signature;
            
            $response = $this->build_request( $args, 'POST')->fetch();

            if (is_wp_error($response)) {
                $this->access_token = $response;
                return $this;
            }
            
            $this->access_token = $response->access_token;
            $this->token_type   = $response->token_type;
            $this->expires_at   = time() + $response->expires_in - 1 ;
            
            return $this->access_token;
        }

        /**
         * Method that checks if current token is expired.
         *
         * @return boolean
         */
        public function is_token_expired(){
            return (time() > $this->expires_at);
        }

    }

}
