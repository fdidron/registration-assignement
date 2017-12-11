<?php
session_start();

if(isset($_SESSION['uid'])) {
  session_destroy();
  unset($_SESSION['uid']);
  unset($_SESSION['username']);
}

header("Location: index.php");
