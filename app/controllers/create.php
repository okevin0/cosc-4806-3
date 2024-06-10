<?php

class Create extends Controller {

    public function index() {		
	    $this->view('create/index');
    }

    public function verify(){
      $username = $_REQUEST['username'];
      $password = $_REQUEST['password'];
  
      $user = $this->model('User');
      $user->authenticate($username, $password); 
    }
}
