<?php
  // Create a register.php page that has a basic register form (username, password, submit)
?>
<!DOCTYPE html>
<html>
  <head>
    <title>Create New Account</title>
  </head>
  <body>
    <h1>Create New Account</h1>
    <?php
      // only print when new user exist
      if(isset($_SESSION['user_exist']) && $_SESSION['user_exist'] > 0 ) {
        echo "The account already exist.";
      }

      // only print when passwords not match
      if(isset($_SESSION['diff_password']) && $_SESSION['diff_password'] > 0 ) {
        echo "<br />passwords not matche.";
      }

      // only print when password length is less than 8
      if(isset($_SESSION['password_length']) && $_SESSION['password_length'] > 0 ) {
        echo "<br />Passwords length should be at least 8 characters.";
      }

      // delete session 
      session_destroy();
    ?>
    <form action="/create/verify" method="post">
      <label for="username">Username:</label>
      <br>
      <input type="text" id="username" name="username">
      <br>
      <label for="password">Password:</label>
      <br>
      <input type="password" id="password" name="password">
      <br>
      <label for="confirm password">Confirm Password:</label>
      <br>
      <input type="password" id="confirm_password" name="confirm password">
      <br><br>
      <input type="submit" value="Submit">
    </form> 

  </body>
</html>