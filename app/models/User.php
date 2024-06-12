<?php

class User {

    public $username;
    public $password;
    public $auth = false;

    public function __construct() {
        
    }

    public function test () {
      $db = db_connect();
      $statement = $db->prepare("select * from users;");
      $statement->execute();
      $rows = $statement->fetch(PDO::FETCH_ASSOC);
      return $rows;
    }

    public function authenticate($username, $password) {
        /*
         * if username and password good then
         * $this->auth = true;
         */
  		$username = strtolower($username);
  		$db = db_connect();
          $statement = $db->prepare("select * from users WHERE username = :name;");
          $statement->bindValue(':name', $username);
          $statement->execute();
          $rows = $statement->fetch(PDO::FETCH_ASSOC);
  		    // print_r($rows['password']);

          // log all login attempts 
          $log_statement = $db->prepare("insert into log (username, attempt, time) values (?, ?, ?);");
          $login_time = date('Y-m-d H:i:s');
          
  		if (password_verify($password, $rows['password'])) {
  			$_SESSION['auth'] = 1;
  			$_SESSION['username'] = ucwords($username);
  			unset($_SESSION['failedAuth']);
        $log_statement->execute([$username, 'good', $login_time]);
  			header('Location: /home');
  			die;
  		} else {
  			if(isset($_SESSION['failedAuth'])) {
  				$_SESSION['failedAuth'] ++; //increment
  			} else {
  				$_SESSION['failedAuth'] = 1;
  			}
        // print_r($login_time);
        $log_statement -> execute([$username, 'bad', $login_time]);
        
  			header('Location: /login');
  			die;
  		}
    }

  // create a new user
  public function create_user ($username, $password) {
    $db = db_connect();
    $statement = $db->prepare("insert into users (username, password) values (?, ?);");
    $new_user = $statement->execute([$username, $password]);
    
    header('Location: /home');
  }
  
  // check if username exists
  public function get_user_by_username ($username, $password) {
    $db = db_connect();
    $statement = $db->prepare("select password from users where username = ?;");
    $statement->execute([$username]);
    $rows = $statement->fetch(PDO::FETCH_ASSOC);

    // if new user, then create
    if (empty($rows)) {
      // hash password, then save to database
      $hash = password_hash($password, PASSWORD_DEFAULT);
      $this->create_user($username, $hash);
    } else {
      // user exist
      return $rows;
    }  
  }

}
