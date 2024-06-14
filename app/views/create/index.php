<?php require_once 'app/views/templates/headerPublic.php'?>
<div class="align-items-center d-flex justify-content-center">
 <div>
    <h1>Create New Account</h1>
    <div class="btn-outline-danger">
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
    </div>
    <form action="/create/verify" method="post">
      <div class="form-group">
        <label for="username">Username:</label>
        <input type="text" class="form-control" id="username" name="username">
      </div>
      <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" class="form-control" id="password" name="password">
      </div>
      <div class="form-group">
        <label for="confirm password">Confirm Password:</label>
        <input type="password" class="form-control" id="confirm_password" name="confirm password">
      </div>
      <br />
      <input type="submit" value="Submit" class="btn btn-primary" style="width: 100%;" > 
    </form> 
   </div>
  </div>
<br />
  <?php require_once 'app/views/templates/footer.php' ?>