<?php

namespace App\Controllers;

use CodeIgniter\Controller;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use ResponseTrait;

require  './vendor/autoload.php';
require_once FCPATH . 'vendor/firebase/php-jwt/src/JWT.php';

class Jwtapi extends Controller
{

    protected $jwt; // Define the $jwt property
    protected $ResponseTrait;
    public function __construct()
    {
        $this->jwt_model = new \App\Models\Jwt();
        $key = 'your_secret_key';
        $algo = 'HS256';
        // Create an instance of the JWT class with the key and algorithm
        $this->jwt = new JWT($key, $algo);
    }

    public function generateTokenx()
    {
        // Example data to encode into the token

        $data = [
            'username' => 'john_doe',
            'email' => 'john@example.com'
        ];
        $id = 123;
        // Define your secret key and algorithm
        // $key = '123q1';
        $key  = '68V0zWFrS72GbpPreidkQFLfj4v9m3Ti+DXc8OB0gcM=';

        $algo = 'HS256';


        // Encode the data into a JWT token
        $token = $this->jwt->encode($data, $key, $algo);


        $data = [
            'scret_key' => $token,
        ];

        $table = 'user';
        $dataupdate = $this->jwt_model->updatesjwt($table, $id, $data);
        // Return the token as JSON response
        return $this->response->setJSON(['token' => $token]);
    }












    // public function decodeToken()
    // {

    //     // Get the token from the request header or wherever it's sent
    //     $token = $this->request->getHeaderLine('Authorization');
    //     try {
    //         $secretKey = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImpvaG5fZG9lIiwiZW1haWwiOiJqb2huQGV4YW1wbGUuY29tIn0.HG6aEdiqqi3x0MIxs8ryv6CwgomtKcFxD47UIVl7XJE';
    //         // Decode the token using the secret key and specify the algorithm
    //         // Assuming $secretKey is the key or secret used to verify the token's signature
    //         $decoded = $this->jwt->decode($token, $secretKey);
    //         // Return the decoded token data as JSON response
    //         return $this->response->setJSON(['decoded' => $decoded]);
    //     } catch (\Exception $e) {
    //         // Handle any exceptions, such as invalid token or signature
    //         return $this->response->setJSON(['error' => $e->getMessage()]);
    //     }
    // }

    public function decodeTokens()
    {
        // Get the token from the request header or wherever it's sent
        $token = $this->request->getHeaderLine('Authorization');
        try {
            // Replace this with your actual secret key
            $secretKey = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImpvaG5fZG9lIiwiZW1haWwiOiJqb2huQGV4YW1wbGUuY29tIn0.HG6aEdiqqi3x0MIxs8ryv6CwgomtKcFxD47UIVl7XJE';
            $hsn = 'HS256';
            // Decode the token using the secret key
            $decoded = \Firebase\JWT\JWT::decode($token, $secretKey, $hsn);

            // Return the decoded token data as JSON response
            return $this->response->setJSON(['decoded' => $decoded]);
        } catch (\Exception $e) {
            // Handle any exceptions, such as invalid token or signature
            return $this->response->setJSON(['error' => $e->getMessage()]);
        }
    }









    // Your other controller methods...


    public function decodeToken()
    {
        $key = getenv('JWT_SECRET');
        $iat = time();
        // current timestamp value
        $exp = $iat + 3600;

        $payload = array(
            "iss" => "Issuer of the JWT",
            "aud" => "Audience that the JWT",
            "sub" => "Subject of the JWT",
            "iat" => $iat, //Time the JWT issued at
            "exp" => $exp, // Expiration time of token
            "email" => '2018surajm@gmail.com',
        );

        $token = JWT::encode($payload, $key, 'HS256');

        $response = [
            'message' => 'Login Successful',
            'token' => $token
        ];

        // Set the content type header to JSON
        header('Content-Type: application/json');

        // Return the response as JSON
        echo json_encode($response);
    }


    // public function verifyToken($token)
    // {



    //     $key = getenv('JWT_SECRET'); // Your secret key



    //     try {
    //         $decoded = JWT::decode($token, new Key($key, 'HS256'));



    //         $expirationTime = $decoded->exp;

    //         // Get the current timestamp
    //         $currentTime = time();

    //         // Check if the token has expired
    //         if ($currentTime >= $expirationTime) {
    //             // Token has expired 
    //             return false;
    //             // You can return false here or handle it accordingly
    //         } else {
    //             // Token is still valid
    //             return true;
    //             // You can return true here or handle it accordingly
    //         }
    //         // Return the decoded payload
    //         // return $decoded;
    //     } catch (\Firebase\JWT\ExpiredException $e) {
    //         // Token expired
    //         return ['error' => 'Token expired'];
    //     } catch (\Firebase\JWT\SignatureInvalidException $e) {
    //         // Invalid token signature
    //         return ['error' => 'Invalid token signature'];
    //     } catch (\Exception $e) {
    //         // Other errors
    //         return ['error' => 'Token verification failed'];
    //     }
    // }






    public function verifyToken($token)
    {
        // print_r('hello');
        // exit();
        $key = getenv('JWT_SECRET'); // Your secret key

        try {
            $decoded = JWT::decode($token, new Key($key, 'HS256'));

            // Get the current timestamp
            $currentTime = time();

            // Check if the token has expired
            if ($currentTime >= $decoded->exp) {
                // Token has expired 
                return ['error' => 'Token expired'];
            } else {
                // Token is still valid
                return true;
            }
        } catch (\Firebase\JWT\ExpiredException $e) {
            // Token expired
            return ['error' => 'Token expired'];
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            // Invalid token signature
            return ['error' => 'Invalid token signature'];
        } catch (\Exception $e) {
            // Other errors
            return ['error' => 'Token verification failed'];
        }
    }

    public function verifyTokenx()
    {





        // Get the token from request header
        //     $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJJc3N1ZXIgb2YgdGhlIEpXVCIsImF1ZCI6IkF1ZGllbmNlIHRoYXQgdGhlIEpXVCIsInN1YiI6IlN1YmplY3Qgb2YgdGhlIEpXVCIsImlhdCI6MTcxMTYyNjIxMiwiZXhwIjoxNzExNjI5ODEyLCJlbWFpbCI6IjIwMThzdXJham1AZ21haWwuY29tIn0.TcsHubP5E3UOuNbNA05JqR6rW-M8RHMw3eIxrYyhDi0';

        //     // Remove 'Bearer ' from the token
        //     $token = str_replace('Bearer ', '', $token);

        //     // Get the secret key from environment variable
        //     $key = '68V0zWFrS72GbpPreidkQFLfj4v9m3Ti+DXc8OB0gcM=';

        //     try {

        //         // Split the JWT token into segments
        //         $jwtSegments = explode('.', $token);

        //         // Decode the header segment
        //         $header = JWT::jsonDecode(JWT::urlsafeB64Decode($jwtSegments[0]));

        //         // print_r($header);
        //         // exit();
        //         // print_r($jwtSegments);
        //         // exit();
        //         // Verify algorithm
        //         $algorithm = $header->alg;
        //         if ($algorithm !== 'HS256') {
        //             throw new \Exception('Invalid algorithm');
        //         }

        //         // Decode the token using HS256 algorithm
        //         $decoded_token = JWT::decode($token, $key, $header);
        //         // echo "xcx";
        //         // exit();

        //         // Token is valid, return decoded token
        //         $response = [
        //             'token' => $decoded_token
        //         ];

        //         // Set the content type header to JSON
        //         header('Content-Type: application/json');

        //         // Return the response as JSON
        //         echo json_encode($response);
        //     } catch (\Firebase\JWT\ExpiredException $e) {
        //         // Token expired
        //         http_response_code(401);
        //         echo json_encode(['error' => 'Token expired']);
        //     } catch (\Firebase\JWT\BeforeValidException $e) {
        //         // Token not yet valid
        //         http_response_code(401);
        //         echo json_encode(['error' => 'Token not yet valid']);
        //     } catch (\Firebase\JWT\SignatureInvalidException $e) {
        //         // Invalid token signature
        //         http_response_code(401);
        //         echo json_encode(['error' => 'Invalid token signature']);
        //     } catch (\Exception $e) {
        //         // Other errors
        //         http_response_code(401);
        //         echo json_encode(['error' => 'Token verification failed']);
        //     }
        // }
    }




    public function  login()
    {

        $client_id = $this->request->getVar('client-id');
        $email = $this->request->getVar('email');
        $password = $this->request->getVar('password');

        if ($client_id == '1234') {

            if ($email == '2018surajm@gmail.com' && $password == '1111') {

                $key = getenv('JWT_SECRET');
                $iat = time();
                // current timestamp value
                $exp = $iat + 3600;

                $payload = array(
                    "iss" => "Issuer of the JWT",
                    "aud" => "Audience that the JWT",
                    "sub" => "Subject of the JWT",
                    "iat" => $iat, //Time the JWT issued at
                    "exp" => $exp, // Expiration time of token
                    "email" => '2018surajm@gmail.com',
                );

                $token = JWT::encode($payload, $key, 'HS256');

                $response = [
                    'message' => 'Login Successful',
                    'token' => $token
                ];
                header('Content-Type: application/json');

                // Return the response as JSON
                echo json_encode($response);
            }
        } else {

            $response = [
                'message' => 'Login Not math Pwd Successful',

            ];
            header('Content-Type: application/json');

            // Return the response as JSON
            echo json_encode($response);
        }
    }


    // public function  dashboardapi()
    // {


    //     $token = $this->request->getVar('token');

    //     $valid_toten = $this->verifyToken($token);

    //     if ($valid_toten  == true) {

    //         $response = [
    //             'message' => 'Successful Show dashboard Ys',
    //             // 'token' => $token
    //         ];
    //         header('Content-Type: application/json');

    //         // Return the response as JSON
    //         echo json_encode($response);
    //     } else {
    //         $response = [
    //             'message' => 'Not valid Api',
    //             // 'token' => $token
    //         ];
    //         header('Content-Type: application/json');

    //         // Return the response as JSON
    //         echo json_encode($response);
    //     }
    // }

    public function dashboardapi()
    {
        // Get the Authorization header
        $header = $this->request->getHeader('Authorization');

        // Check if the header exists and if it contains a token
        if (!$header || !$header->getValue()) {
            // Token is missing or not in the correct format, return an error response
            return $this->sendErrorResponse('Token is missing', 401);
        }

        // Extract the token from the header
        $token = $header->getValue();

        // Verify the token
        $isValidToken = $this->verifyToken($token);

        if ($isValidToken === true) {
            // Token is valid, return a success response
            $response = [
                'message' => 'Successful',
            ];

            // Return the response as JSON
            return $this->response->setJSON($response);
        } else {
            // Token is not valid, return an error response
            return $this->sendErrorResponse('Invalid ', 401);
        }
    }
}
