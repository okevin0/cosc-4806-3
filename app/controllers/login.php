<?php

class Login extends Controller {

    public function index() {		
	    $this->view('login/index');
    }
    
    public function verify(){
			$username = $_REQUEST['username'];
			$password = $_REQUEST['password'];
		
			$user = $this->model('User');
			$isLock = $user->authenticate($username, $password); 

			if($isLock == 'lock') {
				$_SESSION['lock'] = 1;
				$this->view('login/index');
			}
    }

}
