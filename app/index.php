<?php
session_start();

include_once './utils/db.php';

$greeting = isset($_SESSION['uid']) ? 'Hello, '.$_SESSION['username'] : 'Hello, stranger';

$nav = isset($_SESSION['uid']) ? '<a href="/logout.php">Logout</a>' : '<a href="/login.php">Login</a> or <a href="/signup.php">Signup</a>';
?>

<!DOCTYPE html>
  <html>
    <head>
      <title>User Registration Script</title>
      <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" type="text/css" />
    </head>
    <body>
      <div class="container">
        <div class="jumbotron">
          <h1><?php echo $greeting; ?></h1>
          <p><?php echo $nav; ?></p>
        </div>
      </div>
    </body>
  </html>
