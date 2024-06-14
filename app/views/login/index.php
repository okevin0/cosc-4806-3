<?php require_once 'app/views/templates/headerPublic.php'?>
	<div class="align-items-center d-flex justify-content-center">
	<div>
    <div class="page-header" id="banner">
        <div class="row">
            <div class="col-lg-12">
                <h1>You are not logged in</h1>
            </div>
        </div>
    </div>

		<div class="row">
		    <div>
					<div class="btn-outline-warning">
					<?php
						// only print when lock user
						if(isset($_SESSION['lock']) && $_SESSION['lock'] == 1 ) {
							echo "You accound is locked, please try after 60 seconds.";
						}
					?>
					</div>
					<form action="/login/verify" method="post">
					<fieldset>
						<div class="form-group">
							<label for="username">Username</label>
							<input required type="text" class="form-control" name="username">
						</div>
						<div class="form-group">
							<label for="password">Password</label>
							<input required type="password" class="form-control" name="password">
						</div>
			            <br>
					    <button type="submit" class="btn btn-primary " style="width: 100%;">Login</button>
					</fieldset>
					</form> 
					</br>
					<a href="/create">Create New Account</a>
			</div>
		</div>
	</div>
</div>
							
<?php require_once 'app/views/templates/footer.php' ?>
