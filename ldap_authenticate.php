<?php
// This php file will authenticate username and password against a given ldap server and return session variables according to it's group membership

// Initialize session
session_start();
 
function authenticate($user, $password) {

	if(empty($user) || empty($password)) return false;

	// Active Directory server
	$ldap_host = "dc01.home.ronnyvdb.net";
 
	// Active Directory DN
	$ldap_dn = "DC=home,DC=ronnyvdb,DC=net";
 
	// Active Directory user group
	$ldap_user_group = "WebUsers";
 
	// Active Directory manager group
	$ldap_manager_group = "Administrators";
 
	// Domain, for purposes of constructing $user
	$ldap_usr_dom = '@home.ronnyvdb.net';
 
	// connect to active directory
	$ldap = ldap_connect($ldap_host);
 
	// set ldap options
	ldap_set_option ($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
	ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
	
	// verify user and password
	if($bind = @ldap_bind($ldap, $user.$ldap_usr_dom, $password)) {
		// valid
		// check presence in groups
		$filter = "(sAMAccountName=".$user.")";
		$attr = array("memberof");

		$result = ldap_search($ldap, $ldap_dn, $filter, $attr) or exit("Unable to search LDAP server");
		$entries = ldap_get_entries($ldap, $result);
		ldap_unbind($ldap);
 
		
		// check groups
		foreach($entries[0]['memberof'] as $grps) {
			// is manager, break loop
			if(strpos($grps, $ldap_manager_group)) { $access = 2; break; }
 
			// is user
			if(strpos($grps, $ldap_user_group)) $access = 1;
		}
 
		if($access != 0) {
			// establish session variables
			$_SESSION['user'] = $user;
			$_SESSION['access'] = $access;
			return true;
		} else {
			// user has no rights
			return false;
		}
 
	} else {
		// invalid name or password
		return false;
	}
}
?>
