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
     * Identity providers
     */
    private $providers = array();

    /*
     * Known providers configuration
     */
    private $providersConfig = array(

        /*
         *  {
         *     "kind": "plus#personOpenIdConnect",
         *     "gender": "male",
         *     "sub": "110613268514751241292",
         *     "name": "Jérôme Gasperi",
         *     "given_name": "Jérôme",
         *     "family_name": "Gasperi",
         *     "profile": "https://plus.google.com/110613268514751241292",
         *     "picture": "https://lh4.googleusercontent.com/-b2ZwDfR874M/AAAAAAAAAAI/AAAAAAAAAv4/qlnh8V_Y8zA/photo.jpg?sz=50",
         *     "email": "jerome.gasperi@gmail.com",
         *     "email_verified": "true",
         *     "locale": "fr"
         *   }
         */
        'google' => array(
            'externalidpKey' => 'google',
            'protocol' => 'oauth2',
            'accessTokenUrl' => 'https://accounts.google.com/o/oauth2/token',
            'peopleApiUrl' => 'https://www.googleapis.com/plus/v1/people/me/openIdConnect',
            'mapping' => array(
                'email' => 'email',
                'firstname' => 'given_name',
                'lastname' => 'family_name',
                'picture' => 'picture'
            ),
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
        $this->providers = $this->options['providers'] ?? array();
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
                return $this->oauth2($params['issuerId'], $provider);
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
                $profile = $this->oauth2GetProfile($token, $provider);
                break;
            case 'jwt':
                $profile = $this->jwtGetProfile($token, $provider);
                break;
            default:
                RestoLogUtil::httpError(400, 'Unknown sso protocol for issuer "' . $issuerId . '"');
        }

        /*
         * Return resto profile token
         */
        return $this->token($profile, $provider);
    }

    /**
     * Authenticate with generic Oauth2 API
     *
     * @param string $issuerId
     * @param array $provider
     *
     * @return json
     */
    private function oauth2($issuerId, $provider)
    {

        /*
         * Step 1. Get access token
         */
        $accessToken = $this->oauth2GetAccessToken($issuerId, $provider['accessTokenUrl']);

        /*
         * Step 2. Get oauth profile
         */
        $profile = $this->oauth2GetProfile($accessToken, $provider);
        
        /*
         * Insert user in resto database if needed
         */
        $this->createUserInDatabase($profile, $provider);

        return array(
            'token' => $this->token($profile, $provider)
        );
    }

    /**
     * Get OAuth2 access token
     *
     * @param string $issuerId
     * @param string $accessTokenUrl
     *
     * @return string
     */
    private function oauth2GetAccessToken($issuerId, $accessTokenUrl)
    {
        if (!isset($this->data['code']) || !isset($this->data['redirectUri'])) {
            RestoLogUtil::httpError(400);
        }

        $postResponse = json_decode(file_get_contents($accessTokenUrl, false, stream_context_create(array(
            'http' => array(
                'method' => 'POST',
                'header' => 'Content-Type: application/x-www-form-urlencoded',
                'content' => http_build_query(array(
                    'code' => $this->data['code'],
                    'client_id' => $this->providers[$issuerId]['clientId'],
                    'redirect_uri' => $this->data['redirectUri'],
                    'grant_type' => 'authorization_code',
                    'client_secret' => $this->providers[$issuerId]['clientSecret']
                ))
            ),
            'ssl' => $this->options['ssl'] ?? array()
        ))), true);

        return $postResponse['access_token'];
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
        $data = @file_get_contents($provider['peopleApiUrl'], false, stream_context_create(array(
            'http' => array(
                'method' => 'GET',
                'header' => 'Authorization: Bearer ' . $accessToken . (isset($provider['forceJSON']) && $provider['forceJSON'] ? "\r\nx-li-format: json\r\n" : '')
            ),
            'ssl' => $this->options['ssl'] ?? array()
        )));

        if (!$data) {
            RestoLogUtil::httpError(401, 'Unauthorized');
        }

        $profileResponse = json_decode($data, true);

        if (!isset($profileResponse)) {
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
     * @param array $provider
     * @throws Exception
     */
    private function createUserInDatabase($profile, $provider)
    {
        try {
            (new UsersFunctions($this->context->dbDriver))->getUserProfile('email', strtolower($profile[$this->getEmailKey($provider)]));
        } catch (Exception $e) {

            /*
             * User does not exist - create it
             */
            return $this->storeUser($profile, $provider);
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
        if (isset($this->providers[$issuerId])) {

            /*
             * Search for known providers first
             */
            if (isset($this->providersConfig[$issuerId])) {
                $provider = $this->providersConfig[$issuerId];
            } else {
                $provider = $this->providers[$issuerId];
            }
        }

        /*
         * No provider => exit
         */
        if (!isset($provider)) {
            RestoLogUtil::httpError(400, 'No configuration found for issuer "' . $issuerId . '"');
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
    private function token($profile, $provider)
    {
        $emailKey = $this->getEmailKey($provider);

        if (isset($profile[$emailKey])) {
            try {
                $user = new RestoUser(array('email' => $profile[$emailKey]), $this->context, true);
            } catch (Exception $e) {
            }
        }

        // User exists => return JWT
        if (isset($user) && isset($user->profile['id'])) {
            return $this->context->createRJWT($user->profile['id']);
        }

        // User does not exist => Special case - create it
        if (isset($provider['forceCreation']) && $provider['forceCreation']) {
            $restoProfile = $this->storeUser($profile, $provider);
            return $this->context->createRJWT($restoProfile['id']);
        }

        return RestoLogUtil::httpError(401, 'Unauthorized');
    }

    /**
     * Get provider uidKey
     *
     * @param array $provider
     * @return string
     */
    private function getEmailKey($provider)
    {
        foreach ($provider['mapping'] as $key => $value) {
            if ($key === 'email') {
                return $value;
            }
        }
        return 'email';
    }

    /**
     * Store user in database
     *
     * @param  array $profile
     * @param  array $provider
     * @return array
     */
    private function storeUser($profile, $provider)
    {
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

        return (new UsersFunctions($this->context->dbDriver))->storeUserProfile(array_merge($restoProfile, array(
            'activated' => 1,
            'validatedby' => $this->context->core['userAutoValidation'] ? 'auto' : null
        )), $this->context->core['storageInfo']);
    }
}
