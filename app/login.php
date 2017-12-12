<?php
session_start();


//Set a CSRF Token if none were already set in session
if (empty($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(32));
}

include_once './utils/db.php';

function validatePostData($db) {
  $validation = new stdClass;

  $token = filter_input(INPUT_POST, 'token', FILTER_SANITIZE_STRING);
  $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_STRING);
  $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

  $validation->email = $email;
  $validation->password = $password;

  if($_SESSION['token'] != $token) {
    $validation->error = true;
    $validation->message = "CSRF Error";
    return $validation;
  }

  if (!filter_var($email,FILTER_VALIDATE_EMAIL)) {
    $validation->error = true;
    $validation->message = "Invalid email";
    return $validation;
  }

  if (strlen($password) < 8) {
    $validation->error = true;
    $validation->message = "Password must be at least 8 characters";
    return $validation;
  }

  $loginQuery = $db->prepare('SELECT id, username, password FROM users WHERE email = :email');
  $loginQuery->bindParam(':email', $email);

  try{
    $loginQuery->execute();
    $row = $loginQuery->fetch();
    if($row['id']) {
      if(password_verify($password, $row['password'])) {
        $validation->error = false;
        $validation->uid = $row['id'];
        $validation->username = $row['username'];
        return $validation;
      }
    }
  }
  catch( PDOExecption $e) {
    $validation->error = true;
    $validation->message = "Error please retry later";
    return $validation;
  }

  $validation->error = true;
  $validation->message = "Login challenge failed";
  return $validation;

}

if(isset($_POST['login'])) {
  $validation = validatePostData($db);
  if($validation->error == false) {
    $_SESSION['uid'] = $validation->uid;
    $_SESSION['username'] = $validation->username;
  }
}

//Redirect to the home page if already logged in
if(isset($_SESSION['uid'])) {
    header('Location: index.php');
}
?>

<!DOCTYPE html>
  <html>
    <head>
      <title>User Registration Script</title>
      <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" type="text/css" />
    </head>
    <body>
      <div class="container">
        <div class="row">
          <div class="col-xs-12 col-md-6 col-md-offset-3">
            <form role="form" action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post" name="signupform">
              <h1>Login</h1>
              <div class="form-group">
                <input class="form-control" type="email" name="email" placeholder="Enter email" required value="<?php echo $validation->email ?>" />
              </div>
              <div class="form-group">
                <input class="form-control" type="password" name="password" placeholder="Enter password" required value="<?php echo $validation->password ?>" />
              </div>
              <div class="form-group">
                <input type="submit" name="login" value="Sign Up" class="btn btn-primary" />
              </div>
              <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>" />
            </form>
          <?php if($validation->error) { ?>
            <p><?php echo $validation->message ?></p>
          <?php } ?>
          </div>
        </div>
      </div>
    </body>
  </html>

