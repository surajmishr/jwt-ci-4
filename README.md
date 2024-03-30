# jwt-ci-4 Documaintation 
First Install Jwt composer 
Then  
Set .env file
JWT_SECRET = 'JWT SECRET KEY SAMPLE HERE'
 
Then Open Filters  Implement app/Filters/AuthFilter.php 
app/Config/Filters.php 
Help website
https://www.binaryboxtuts.com/php-tutorials/codeigniter-4-json-web-tokenjwt-authentication/

$routes->group("api", function ($routes) {
    $routes->post("register", "Register::index");
    $routes->post("login", "Login::index");
    $routes->get("users", "User::index", ['filter' => 'authFilter']);
});
