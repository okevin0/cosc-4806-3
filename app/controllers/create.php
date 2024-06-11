<?php

class Create extends Controller {
// new controller fore create new account
    public function index() {		
	    $this->view('create/index');
    }

    public function verify(){
      $username = $_REQUEST['username'];
      $password = $_REQUEST['password'];
      $confirm_password = $_REQUEST['confirm_password'];

      // check password match and need to meet a minimum security standard
      if ($password != $confirm_password) {
        $_SESSION['diff_password'] = 1;
        // echo "diff password"; die;
        $this->view('create/index');
      } 

      if (strlen($password) < 8) {
        $_SESSION['password_length'] = 1;
        $this->view('create/index');
      }

      // call model to check if username exist, if not then create new account
      if($password == $confirm_password && strlen($password) > 7) {
        // echo 1; die;
         $check_user = $this->model('User');
         $check_user->get_user_by_username($username, $password); 
          
          // Check to see if the account name exists already
          if (!empty($check_user)) {
            // if user exist, redirect to regiser page
            $_SESSION['user_exist'] = 1;
            $this->view('create/index');
          }
      }   
    }
}
