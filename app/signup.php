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
  $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
  $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_STRING);
  $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
  $password2 = filter_input(INPUT_POST, 'password2', FILTER_SANITIZE_STRING);

  $validation->username = $username;
  $validation->email = $email;
  $validation->password = $password;

  if($_SESSION['token'] != $token) {
    $validation->error = true;
    $validation->message = "CSRF Error";
    return $validation;
  }

  if (!preg_match("/^[a-zA-Z0-9]+$/",$username)) {
    $validation->error = true;
    $validation->message = "Username must contain only alphanumeric characters";
    return $validation;
  }

  $userExists = $db->prepare('SELECT id FROM users WHERE username = :username');
  $userExists->bindParam(':username', $username);

  try{
    $userExists->execute();
    $row = $userExists->fetch();
    if($row['id']) {
      $validation->error = true;
      $validation->message = "Username already taken";
      return $validation;
    }
  }
  catch( PDOExecption $e) {
      $validation->error = true;
      $validation->message = "Error please retry later";
      return $validation;
  }
   

  if (!filter_var($email,FILTER_VALIDATE_EMAIL)) {
    $validation->error = true;
    $validation->message = "Invalid email";
    return $validation;
  }

  $emailExists = $db->prepare('SELECT id FROM users WHERE email = :email');
  $emailExists->bindParam(':email', $email);

  try{
    $emailExists->execute();
    $row = $emailExists->fetch();
    if($row['id']) {
      $validation->error = true;
      $validation->message = "Username already taken";
      return $validation;
    }
  }
  catch( PDOExecption $e) {
      $validation->error = true;
      $validation->message = "Error please retry later";
      return $validation;
  }
  if (strlen($password) < 8) {
    $validation->error = true;
    $validation->message = "Password must be at least 8 characters";
    return $validation;
  }

  if ($password != $password2) {
    $validation->error = true;
    $validation->message = "The two passwords must match";
    return $validation;
  }

  $validation->error = false;
  return $validation;

}

if(isset($_POST['signup'])) {
  $validation = validatePostData($db);
  if($validation->error == false) {
    $query = $db->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password");
    $query->bindParam(':username', $validation->username);
    $query->bindParam(':email', $validation->email);
    $query->bindParam(':password', password_hash($validation->password, PASSWORD_BCRYPT));
    try{
      $query->execute();
      $_SESSION['uid'] = $db->lastInsertId();
    }
    catch( PDOExecption $e) {
      print "Error!: " . $e->getMessage() . "</br>";
    }
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
              <h1>Signup</h1>
              <div class="form-group">
                <input class="form-control" type="text" name="username" placeholder="Enter username" required value="<?php echo $validation->username ?>" />
              </div>
              <div class="form-group">
                <input class="form-control" type="email" name="email" placeholder="Enter email" required value="<?php echo $validation->email ?>" />
              </div>
              <div class="form-group">
                <input class="form-control" type="password" name="password" placeholder="Enter password" required value="<?php echo $validation->password ?>" />
              </div>
              <div class="form-group">
                <input class="form-control" type="password" name="password2" placeholder="Confirm password" required value="<?php echo $validation->password2 ?>" />
              </div>
              <div class="form-group">
                <input type="submit" name="signup" value="Sign Up" class="btn btn-primary" />
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
