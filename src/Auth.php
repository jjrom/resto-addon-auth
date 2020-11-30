<?php
/*
 * Copyright 2018 Jérôme Gasperi
 *
 * Licensed under the Apache License, version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/**
 * Authentication add-on
 *
 * This add-on allows authentication from SSO servers
 *
 * Predefiend supported authentication servers :
 *      - Google
 *      - Linkedin
 *
 * Generic supported authentication method :
 *      - OAuth 1.0
 *      - OAuth 2.0
 *
 */
class Auth extends RestoAddOn
{

    /**
     * Add-on version
     */
    public $version = '1.0';

    /*
     * Data
     */
    private $data = array();

    /*
     * Known providers configuration
     */
    private $providersConfig = array(

        /*
         * Google
         */
        'google' => array(
            'externalidpKey' => 'google',
            'protocol' => 'oauth2',
            'accessTokenUrl' => 'https://accounts.google.com/o/oauth2/token',
            'peopleApiUrl' => 'https://people.googleapis.com/v1/people/me?personFields=emailAddresses,names,nicknames,photos',
            'forceCreation' => true
        ),

        /*
         * Authentication with google using the JWT token
         *
         *  {
         *      "iss": "https://accounts.google.com",
         *      "iat": "1486397062",
         *      "exp": "1486400662",
         *      "at_hash": "WW7VOi8A3sdOkQufbJxozg",
         *      "aud": "426412538974-ncfcdep7n4estpg52vplojijcvea2ese.apps.googleusercontent.com",
         *      "sub": "110613268514751241292",
         *      "email_verified": "true",
         *      "azp": "426412538974-ncfcdep7n4estpg52vplojijcvea2ese.apps.googleusercontent.com",
         *      "email": "jerome.gasperi@gmail.com",
         *      "name": "Jérôme Gasperi",
         *      "picture": "https://lh4.googleusercontent.com/-b2ZwDfR874M/AAAAAAAAAAI/AAAAAAAAAv4/qlnh8V_Y8zA/s96-c/photo.jpg",
         *      "given_name": "Jérôme",
         *      "family_name": "Gasperi",
         *      "locale": "fr",
         *      "alg": "RS256",
         *      "kid": "2f7c552b3b91db466e73f0972c8a2b19c5f0dd8e"
         *  }
         */
        'googlejwt' => array(
            'externalidpKey' => 'google',
            'protocol' => 'jwt',
            'validationUrl' => 'https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=',
            'checkProperty' => 'sub',
            'mapping' => array(
                'email' => 'email',
                'firstname' => 'given_name',
                'lastname' => 'family_name',
                'picture' => 'picture'
            ),
            'forceCreation' => true
        ),

        /*
         * linkedin
         *
         *  {
         *      "emailAddress": "john.doe@dev.null",
         *      "firstName": "John",
         *      "id": "xxxx",
         *      "lastName": "Doe",
         *      "pictureUrl": "https:\\\/\\\/media.licdn.com\\\/mpr\\\/mprx\\\/dvsdgfsdfgs9B-TjLa1rdXl2a"
         *  }
         *
         */
        'linkedin' => array(
            'externalidpKey' => 'linkedin',
            'protocol' => 'oauth2',
            'accessTokenUrl' => 'https://www.linkedin.com/uas/oauth2/accessToken',
            'peopleApiUrl' => 'https://api.linkedin.com/v1/people/~:(id,first-name,last-name,email-address,picture-url)',
            'mapping' => array(
                'email' => 'emailAddress'
            ),
            'forceJSON' => true
        ),

        /*
         * facebook
         *
         *  {
         *      "email": "john.doe@dev.null",
         *      "name": "John",
         *      "id": "xxxx"
         *  }
         *
         */
        'facebook' => array(
            'externalidpKey' => 'facebook',
            'protocol' => 'oauth2',
            'accessTokenUrl' => 'https://graph.facebook.com/oauth/access_token',
            'peopleApiUrl' => 'https://graph.facebook.com/me/?fields=email,first_name,last_name,id',
            'mapping' => array(
                'email' => 'email',
                'firstname' => 'first_name',
                'lastname' => 'last_name'
            ),
            'forceCreation' => true
        ),

        /*
         * Theia
         */
        'theia' => array(
            'externalidpKey' => 'theia',
            'protocol' => 'oauth2',
            'accessTokenUrl' => 'https://sso.theia-land.fr/oauth2/token',
            'peopleApiUrl' => 'https://sso.theia-land.fr/oauth2/userinfo?schema=openid',
            'forceCreation' => true
        )

    );

    /**
     * Constructor
     *
     * @param RestoContext $context
     * @param RestoContext $user
     */
    public function __construct($context, $user)
    {
        parent::__construct($context, $user);
    }

    /**
     * Main function - return authentication token as JWT
     *
     * @param array $params : route parameters
     * @param array $data : POST or PUT parameters
     *
     * @return string
     */
    public function authenticate($params, $data = array())
    {
        if (!$this->context) {
            RestoLogUtil::httpError(500, 'Invalid Context');
        }

        // Authentication issuer is mandatory
        if (!isset($params) || !isset($params['issuerId'])) {
            RestoLogUtil::httpError(400, 'Missing issuerId');
        }

        /*
         * Set POST data from resto
         */
        $this->data = $data;

        /*
         * Get provider
         */
        $provider = $this->getProvider($params['issuerId']);
        
        /*
         * Authenticate from input protocol
         */
        switch ($provider['protocol']) {
            case 'oauth2':
                return $this->oauth2($provider);
            default:
                RestoLogUtil::httpError(400, 'Unknown sso protocol for issuer "' . $params['issuerId'] . '"');

        }
    }

    /**
     * Return user profile from token key
     *
     * @param string $token
     */
    public function getProfileToken($issuerId, $token)
    {

        /*
         * Get provider
         */
        $provider = $this->getProvider($issuerId);

        /*
         * Get profile from SSO issuer
         */
        switch ($provider['protocol']) {
            case 'oauth2':
                $profile = $this->convertProfile($this->oauth2GetProfile($token, $provider), $provider['externalidpKey'] ?? 'unknown');
                break;
            case 'jwt':
                $profile = $this->convertProfile($this->jwtGetProfile($token, $provider), $provider['externalidpKey'] ?? 'unknown');
                break;
            default:
                RestoLogUtil::httpError(400, 'Unknown sso protocol for issuer "' . $issuerId . '"');
        }

        /*
         * Return resto profile token
         */
        return $this->tokenAndProfile($profile, $provider)['token'];
    }

    /**
     * Authenticate with generic Oauth2 API
     *
     * @param array $provider
     *
     * @return json
     */
    private function oauth2($provider)
    {

        /*
         * Step 1. Get access token
         */
        $accessToken = $this->oauth2GetAccessToken($provider);

        /*
         * Step 2. Get oauth profile
         */
        $profile = $this->convertProfile($this->oauth2GetProfile($accessToken, $provider), $provider['externalidpKey'] ?? 'unknown');
        
        /*
         * Insert user in resto database if needed
         */
        $this->createUserInDatabase($profile);

        return $this->tokenAndProfile($profile, $provider);
    }

    /**
     * Get OAuth2 access token
     *
     * @param array $provider
     *
     * @return string
     */
    private function oauth2GetAccessToken($provider)
    {
        if (!isset($this->data['code']) || !isset($this->data['redirectUri'])) {
            RestoLogUtil::httpError(400);
        }

        try {
            $curl = new Curly();
            $params = array(
                'code' => $this->data['code'],
                'client_id' => $provider['clientId'],
                'redirect_uri' => $this->data['redirectUri'],
                'grant_type' => 'authorization_code',
                'client_secret' => $provider['clientSecret']
            );
            $postResponse = json_decode($curl->post($provider['accessTokenUrl'], json_encode($params)), true);
            $curl->close();
        } catch (Exception $e) {
            $curl->close();
            RestoLogUtil::httpError($e->getCode(), $e->getMessage());
        }

        if ( isset($postResponse['error']) ) {
            RestoLogUtil::httpError(400, $postResponse['error']);
        }
        
        return $postResponse['access_token'] ?? null;
    }

    /**
     * Return resto profile using from OAuth2 server
     *
     * @param string $accessToken
     *
     * @throws Exception
     */
    private function oauth2GetProfile($accessToken, $provider)
    {

        try {
            $curl = new Curly();
            $curl->setHeaders(array(
                'Content-Type: application/json',
                'Accept: application/json',
                'Authorization: Bearer ' . $accessToken . (isset($provider['forceJSON']) && $provider['forceJSON'] ? "\r\nx-li-format: json\r\n" : '')
            ));
            $profileResponse = json_decode($curl->get($provider['peopleApiUrl']), true);
            $curl->close();
        } catch (Exception $e) {
            $curl->close();
            RestoLogUtil::httpError($e->getCode(), $e->getMessage());
        }

        if ( !isset($profileResponse) ) {
            RestoLogUtil::httpError(401, 'Unauthorized');
        }

        return $profileResponse;
    }

    /**
     * Return resto profile using from JWT token
     *
     * @param string $token
     *
     * @throws Exception
     */
    private function jwtGetProfile($jwt, $provider)
    {
        $data = @file_get_contents($provider['validationUrl'] . $jwt, false, stream_context_create(array(
            'http' => array(
                'method' => 'GET'
            ),
            'ssl' => isset($this->options['ssl']) ? $this->options['ssl'] : array()
        )));

        if (!$data) {
            RestoLogUtil::httpError(401, 'Unauthorized');
        }

        $profileResponse = json_decode($data, true);

        // 'checkProperty' must be present otherwise there is an error
        if (!isset($profileResponse) || !isset($profileResponse[$provider['checkProperty']])) {
            RestoLogUtil::httpError(401, 'Unauthorized');
        }

        return $profileResponse;
    }

    /**
     * Insert user into resto database if needed
     *
     * @param array $profile
     * @throws Exception
     */
    private function createUserInDatabase($profile)
    {
        try {
            (new UsersFunctions($this->context->dbDriver))->getUserProfile('email', strtolower($profile['email']));
        } catch (Exception $e) {
            
            /*
             * User does not exist - create it
             */
            return $this->storeUser($profile);
        }

        return false;
    }

    /**
     * Return SSO provider
     *
     * @param string $issuerId
     */
    private function getProvider($issuerId)
    {

        /*
         * Get providers from input ADDON_AUTH_PROVIDERS
         */
        $providers = $this->getProviders($this->options['providers'] ?? null);

        /*
         * No provider => exit
         */
        if ( !isset($providers[$issuerId])) {
            RestoLogUtil::httpError(400, 'No configuration found for issuer "' . $issuerId . '"');
        }

        /*
         * Search for known providers first
         */
        if (isset($this->providersConfig[$issuerId])) {
            $provider = array_merge($this->providersConfig[$issuerId], $providers[$issuerId]);
        } else {
            $provider = $providers[$issuerId];
        }
       
        return $provider;
    }

    /**
     * Return profile token if profile exist - throw exception otherwise
     *
     * @param Array $profile
     * @param Array $provider
     * @return json
     */
    private function tokenAndProfile($profile, $provider)
    {

        if (isset($profile['email'])) {
            try {
                $user = new RestoUser(array('email' => strtolower($profile['email'])), $this->context, true);
            } catch (Exception $e) {
            }
        }

        // User exists => return JWT
        if (isset($user) && isset($user->profile['id'])) {
            return array(
                'token' => $this->context->createRJWT($user->profile['id']),
                'profile' => $user->profile
            );
        }

        // User does not exist => Special case - create it
        if (isset($provider['forceCreation']) && $provider['forceCreation']) {
            $restoProfile = $this->storeUser($profile);
            return array(
                'token' => $this->context->createRJWT($restoProfile['id']),
                'profile' => $restoProfile
            );
        }

        return RestoLogUtil::httpError(401, 'Unauthorized');
    }

    /**
     * Store user in database
     *
     * @param  array $profile
     * @param  array $provider
     * @return array
     */
    private function storeUser($profile)
    {

        /*
        $restoProfile = array();

        // Initialize externalidp
        $externalidp = array();
        $externalidp[$provider['externalidpKey']] = $profile;

        foreach ($provider['mapping'] as $key => $value) {
            if (isset($profile[$value])) {
                $restoProfile[$key] = $key === 'email' ? strtolower($profile[$value]) : $profile[$value];
            }
        }

        // Facebook special case (picture is not set by default)
        if ($provider['externalidpKey'] === 'facebook') {
            $restoProfile['picture'] = 'https://graph.facebook.com/' . $profile['id'] . '/picture?type=large';
            $externalidp[$provider['externalidpKey']]['picture'] = $restoProfile['picture'];

            // Special case where facebook does not provide an email adress - create it from facebook id
            if (!isset($restoProfile['email'])) {
                $restoProfile['email'] = $profile['id'] . '@facebook.com';
            }
        }

        // Compute default name from "firstname lastname"
        $restoProfile['name'] = trim(join(' ', array(ucfirst($restoProfile['firstname'] ?? ''), ucfirst($restoProfile['lastname'] ?? ''))));

        // Encode externalidp
        $restoProfile['externalidp'] = json_encode($externalidp, JSON_UNESCAPED_SLASHES);
        */
        return (new UsersFunctions($this->context->dbDriver))->storeUserProfile(array_merge($profile, array(
            'activated' => 1,
            'validatedby' => $this->context->core['userAutoValidation'] ? 'auto' : null
        )), $this->context->core['storageInfo']);
    }

    /**
     * Convert profile from provider to resto profile
     * 
     * @param {Array} $profile
     * @param {string} $providerName
     */
    private function convertProfile($profile, $providerName)
    {
        switch ($providerName) {

            case 'google':
                return $this->convertGoogle($profile);

            case 'facebook':
                return $this->convertFacebook($profile);

            case 'theia':
                return $this->convertTheia($profile);

            default:
                return $profile;
        }

    }

    /**
     * Return resto profile from google profile
     * 
     * {
     *      "resourceName": "people/110613268514751241292",
     *      "names":[
     *          {
     *              "displayName":"Jérôme Gasperi",
     *              "familyName":"Gasperi",
     *              "givenName":"Jérôme",
     *              "displayNameLastFirst":"Gasperi, Jérôme",
     *              "unstructuredName":"Jérôme Gasperi"
     *          }
     *      ],
     *      "nicknames":[
     *          {
     *              "value":"jrom",
     *              "type":"ALTERNATE_NAME"
     *          }
     *      ],
     *      "photos":[
     *          {
     *              "url":"https://lh3.googleusercontent.com/a-/AOh14GgIJitSkG_3bc-dHO3O2o-j7Zs5F0mJdH4PNjJRrA=s100"
     *          }
     *      ],
     *      "emailAddresses":[
     *          {
     *              "metadata":{
     *                  "source":{
     *                      "id":110613268514751241292
     *                  }
     *              }
     *              "value": "Jerome.Gasperi@gmail.com"
     *          }
     *      ]
     *  }
     * 
     * @param {Array} $profile
     * @return {Array}
     */
    private function convertGoogle($profile)
    {

        $restoProfile = array(
            'email' => isset($profile['emailAddresses']) &&  isset($profile['emailAddresses'][0]) ? $profile['emailAddresses'][0]['value'] : null,
            'firstname' => isset($profile['names']) &&  isset($profile['names'][0]) ? $profile['names'][0]['givenName'] : null,
            'lastname' => isset($profile['names']) &&  isset($profile['names'][0]) ? $profile['names'][0]['familyName'] : null,
            'name' => isset($profile['names']) &&  isset($profile['names'][0]) ? $profile['names'][0]['displayName'] : null,
            'picture' => isset($profile['photos']) &&  isset($profile['photos'][0]) ? $profile['photos'][0]['url'] : null,
            'externalidp' => array(
                'google' => $profile
            )
        );

        return $restoProfile;

    }

    /**
     * Convert facebook profile to resto profile
     * 
     * @param {Array} $profile
     * @return {Array}
     */
    private function convertFacebook($profile)
    {
        return $profile;
    }

    /**
     * Convert theia profile to resto profile
     * 
     * @param {Array} $profile
     * @return {Array}
     */
    private function convertTheia($profile)
    {
        return $profile;
    }

    /**
     * Get providers from input string $str
     * Format of $str is
     * 
     *  providerId1|clientId1|clientSecret1;providerId2|clientId2|clientSecret2;...etc...
     * 
     * @param {String} $str
     */
    private function getProviders($str)
    {
        $providers = array();

        if ( !isset($str) ) {
            return $providers;
        }

        $arr = explode(';', $str);
        for ($i = 0, $ii = count($arr); $i < $ii; $i++) {
            $split = explode('|', $arr[$i]);
            $providers[trim($split[0])] = array(
                'clientId' => trim($split[1]),
                'clientSecret' => trim($split[2])
            );
        }

        return $providers;

    }
}
