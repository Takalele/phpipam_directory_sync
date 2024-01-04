#!/usr/bin/php
<?php

// Load modules
$module_path = "/phpipam"
require_once($module_path . "/functions/functions.php");
include($module_path . "/functions/adLDAP/src/adLDAP.php");
require_once($module_path . "/phpipam/config.php");

///////////////////////////////////////////////////////////////////// V A R I A B L E S  -  T O    B E    S E T ///////////////////////////////////////////////////////////////////////

//////////////////////////
// Directory
//////////////////////////
// Auth Methode (e.g. AD <- only AD is tested!)
$auth_method = "AD";
// emtpy if you want to search the whole directory or set it to a specific DN like "OU=phpipam,OU=Applications,DC=example,DC=tld"
$search_dn = "";
// Search filter Groupname Startwith(eg.: PHPIPPAM), If Empty, it searches every Group in given Search_DN.
$search_group_prefix = "PHPIPPAM_";

//////////////////////////
// User + Group Settings
//////////////////////////
// Admin-Group Name
$admin_group_name = "PHPIPPAM_ADMINS";
// Date format for description of imported groups / users
$date_format = "d.m.Y";
// Default language (I_id from "lang" db-table - e.g. 1=en_GB, 5=de_DE)
$lang_id = 5;
// Enable e-mail notifications for new created user
$mail_notify = "Yes";
// Enable e-mail change log
$mail_changelog = "Yes";
// Default widgets for new users
$default_widgets['Administrator'] = '{"vlan":"1","vrf":"1","pdns":"1","circuits":"1","racks":"1","nat":"1","pstn":"1","customers":"1"}';
$default_widgets['User'] = '{"vlan":"1","vrf":"1","pdns":"1","circuits":"1","racks":"1","nat":"1","pstn":"1","customers":"1"}';


///////////////////////////////////////////////////////////////////////////////// V A R I A B L E S ///////////////////////////////////////////////////////////////////////////////////

// Do not edit
$phpipam_groups = [];
$phpipam_current_user_groups = [];
$directory_group_members = [];

////////////////////////////////////////////////////////////////////////////////// F U N C T I O N S //////////////////////////////////////////////////////////////////////////////////

// Sort the phpipam user group for easier use
function phpipam_user_group_membership_sort ($array) {
    $phpipam_user_data;
    // Return empty array, if no data
    if (!$array) { return array();}
    // Else sort
    foreach ($array as $array_nr) {
        $phpipam_user_data[$array_nr->username]['groups'] = [];
        foreach ($array_nr as $key=>$value) { 
            if ($key == "groups") {
                foreach ( explode(",",$value) as $groupid) {
                    $tmp = explode(':', str_replace('"', "", preg_replace(array('/{/', '/}/'), "",  $groupid))); 
                    if(sizeof($tmp) == 2) { 
                        $phpipam_user_data[$array_nr->username]['groups'][$tmp[0]] = $tmp[1];
                    }
                }
            }
            else { 
                $phpipam_user_data[$array_nr->username][$key] = $value;
            }
        }
    }
    return $phpipam_user_data;
}

////////////////////////////////////////////////////////////////////////////// T H E    P R O G R A M M ///////////////////////////////////////////////////////////////////////////////

// Echo header
echo "---------------------------------------------------------------------------\n";
echo "|                D I R E C T O R Y   S Y N C                              |\n";
echo "---------------------------------------------------------------------------\n";
echo "\n";

// Initialize DB
$Database 	= new Database_PDO;
$User 		= new User ($Database);
$Admin	 	= new Admin ($Database);
$Result 	= new Result ();

// Parse parameter from Database
$db = new Database_PDO;
$server = $db->getObjectQuery("SELECT * FROM usersAuthMethod WHERE type='$auth_method' LIMIT 0, 1");
$auth_methodId = $server->id;
$params = pf_json_decode($server->params);
$base_dn=$params->base_dn;
$controllers =  pf_explode(";",str_replace(" ", "", $params->domain_controllers));

if($search_dn) { $base_dn=$search_dn; }

// Get phpipam groups from database and sort them for easier use later
$groups_in_phpipam_db = $Admin->fetch_all_objects ("userGroups", "g_id");
if ($groups_in_phpipam_db) {
    foreach ($groups_in_phpipam_db as $array_nr) {
        foreach ($array_nr as $key=>$value) { 
            $phpipam_groups[$array_nr->g_name][$key] = $value;
        }
    }
}

// Test if login parameters available
if (is_blank(@$params->adminUsername) || is_blank(@$params->adminPassword))	{ $Result->show("danger", _("Missing credentials"), true); }

try {
    //////////////////////////////////////////////
    // Open directory connection
    //////////////////////////////////////////////
	if($server->type == "NetIQ") { $params->account_suffix = ""; }
	// Set options
    $options_base_dn = array(
        'base_dn'=>$params->base_dn,
        'account_suffix'=>$params->account_suffix,
        'domain_controllers'=>pf_explode(";",$params->domain_controllers),
        'use_ssl'=>$params->use_ssl,
        'use_tls'=>$params->use_tls,
        'ad_port'=>$params->ad_port,
        );
	$options_search_dn = array(
        'base_dn'=>$base_dn,
        'account_suffix'=>$params->account_suffix,
        'domain_controllers'=>pf_explode(";",$params->domain_controllers),
        'use_ssl'=>$params->use_ssl,
        'use_tls'=>$params->use_tls,
        'ad_port'=>$params->ad_port,
        );

	// Create providers
    $directory_base_dn = new adLDAP($options_base_dn);
    $authUser = $directory_base_dn->authenticate($params->adminUsername, $params->adminPassword);
	$directory_search_dn = new adLDAP($options_search_dn);
    $authUser = $directory_search_dn->authenticate($params->adminUsername, $params->adminPassword);
    
    // Try to login with higher credentials for search
	$authUser = $directory_search_dn->authenticate($params->adminUsername, $params->adminPassword);
    if (isset($params->adminUsername) && isset($params->adminPassword)) {
		$authUser = $directory_search_dn->authenticate($params->adminUsername, $params->adminPassword);
		if (!$authUser) {
			$Result->show("danger", _("Invalid credentials"), true);
		}
	}
	if ($authUser == false) {
		$Result->show("danger", _("Invalid credentials"), true);
	}

    if($server->type == "LDAP") { $directory_search_dn->setUseOpenLDAP(true); }

    // HINT: Remove the @ before $directory_search_dn, to enable error-messages again (supressed due warning when ad-descriptions are empty)
    if($search_group_prefix) {
        echo "Searching for groups with prefix '" . $search_group_prefix . "' in DN:" . $base_dn . "\n";
        $search_filter = ldap_escape($search_group_prefix, null, LDAP_ESCAPE_FILTER);
        $groups = @$directory_search_dn->group()->search(adLDAP::ADLDAP_SECURITY_GLOBAL_GROUP, true, "$search_filter*");
    } else {
        echo "Searching for groups in DN:" . $base_dn . "\n";
        $search_filter = ldap_escape("", null, LDAP_ESCAPE_FILTER);
        $groups = @$directory_search_dn->group()->search(adLDAP::ADLDAP_SECURITY_GLOBAL_GROUP, true, "$search_filter*");
    }
	
    echo "\n";
    echo "-------------------------\n";
    echo "Groups found in Directory\n";
    echo "-------------------------\n";

    // Check if directory groups where found, and if not, create them
    if ($groups) {
        // Loop over found groups
        foreach ($groups as $group=>$desc) {
            echo "Directory group: " . $group . "\n";
            echo "  Description: " . $desc . "\n";

            //////////////////////////////////////////////
            // Check if group already exists in phpipam
            //////////////////////////////////////////////
            if (array_key_exists($group, $phpipam_groups)) {
                echo "  Exists in phpipam: YES\n";
            }
            else {
                echo "  Exists in phpipam: NO\n";
                // Create group in phpipam
                $values = array(
                    "g_name"=>$group,
                    "g_desc"=>$desc . " (imported from directory on ". date($date_format,time()) .")"
                );
                if (!$Admin->object_modify("userGroups", "add", "g_id", $values)) { 
                    $Result->show("danger",  _("Group")." "."add"." "._("error")."!", false); 
                }
                else { 
                    echo "  Group (created)\n"; 
                    // Get new created phpipam group id
                    $groups_in_phpipam_db_tmp = $Admin->fetch_object ("userGroups", "g_name", $group );
                    foreach ($groups_in_phpipam_db_tmp as $key=>$value) { 
                        $phpipam_groups[$group][$key] = $value;
                    }
                }
            }

            //////////////////////////////////////////////
            // Check members, add them to groups and create them if missing
            //////////////////////////////////////////////
            echo "  Members in phpipam db:\n";
            // Get group members from directory
            $directory_group_members[$group] = @$directory_base_dn->group()->members($group) ?: [];
            // Get members in directory admin group
            $directory_admin_group_members;
            foreach ($directory_base_dn->group()->members($admin_group_name) as $admin) {
                $directory_admin_group_members[$admin] = $admin;
            }

            // Get all users in group from phpipam db
            $phpipam_user_data_tmp = $Admin->fetch_multiple_objects ("users", "authMethod", $auth_methodId, $sortField = 'id', $sortAsc = true, $like = false, $result_fields = "*");
            // Make it easier to access
            $phpipam_user_data = phpipam_user_group_membership_sort($phpipam_user_data_tmp);

            if (!empty($directory_group_members[$group])) {
                $reload_add_group_member = 0;
                foreach($directory_group_members[$group] as $directory_member) {
                    // Get directory user data
                    $directory_member_data = $directory_base_dn->user()->info($directory_member);
                    // Check if member exists in phpipam db
                    $member_exists = $Admin->fetch_object ("users", "username", $directory_member);
                    if (empty($member_exists)) {
                        // Create user
                        if ($directory_member_data['count'] != 1) { 
                            echo "      ERROR: More than one user found with samaccountname: ".$directory_member . "\n";
                        }
                        else {
                            // Define user-role (Default: User)
                            $role = "User";
                            if ( array_key_exists($directory_member, $directory_admin_group_members) ) { 
                                $role = "Administrator";
                            }

                            $values = array(
                                "username"       =>$directory_member,
                                "real_name"      =>$directory_member_data[0]['displayname'][0],
                                "email"          =>$directory_member_data[0]['mail'][0],
                                "role"           =>$role,
                                "widgets"        =>$default_widgets[$role],
                                "authMethod"     =>$auth_methodId,
                                "lang"           =>$lang_id,
                                "mailNotify"     =>$mail_notify,
                                "mailChangelog"  =>$mail_changelog,
                                "theme"          =>"default",
                                "disabled"       =>"No",
                                "editdate"       =>date("Y-m-d h:m:s",time())
                                );

                            if (!$Admin->object_modify("users", "add", "id", $values)) { 
                                $Result->show("danger",  _("Users")." "."add"." "._("error")."!", false); 
                            }
                            else { 
                                echo "    ".escape_input($directory_member) . " (created)\n"; 
                                // Update user data
                                $member_exists = $Admin->fetch_object ("users", "username", $directory_member);
                            }
                        }
                    }
                    // Split / save groups for easier use
                    $phpipam_user_groups = [];
                    foreach ( explode(",", $member_exists->groups) as $row=>$value) {
                        $tmp = explode(':', str_replace('"', "", preg_replace(array('/{/', '/}/'), "",  $value))); 
                        if(sizeof($tmp) == 2) { $phpipam_user_groups[$tmp[0]] = $tmp[1]; }
                    }
                    // Add user to group (if missing)
                    if (!array_key_exists($phpipam_groups[$group]['g_id'], $phpipam_user_groups )) {
                        // lets add the groups manually, because the function "add_group_to_user" has a bug and overwrites the data sometimes
                        $phpipam_user_groups[ $phpipam_groups[$group]['g_id'] ] = $phpipam_groups[$group]['g_id'];
                        $new_groups = json_encode($phpipam_user_groups);
                        if (!$Admin->object_modify("users", "edit", "id", array("id"=>$member_exists->id, "groups"=>$new_groups))) {
                            $Result->show("danger",  _("Users")." "."'add group to user'"." "._("error")."!", false); 
                        }
                        else {
                            echo "    ".escape_input($directory_member) . " (added)\n";
                            // Update data (later)
                            $reload_add_group_member = 1;
                        }
                    }
                    else {
                        echo "    ".escape_input($directory_member) . "\n";
                    }

                    // Check if role has changed
                    $values = [];
                    if (array_key_exists($directory_member, $directory_admin_group_members)) {
                        if (array_key_exists($directory_member, $phpipam_user_data) and $phpipam_user_data[$directory_member]['role'] == 'User') {
                            // Set me as admin
                            $values = array( 
                                "id"             =>$phpipam_user_data[$directory_member]['id'] ,
                                "role"           =>"Administrator",
                                "widgets"        =>$default_widgets['Administrator'] 
                            );
                        }
                    }
                    else { 
                        if (array_key_exists($directory_member, $phpipam_user_data) and $phpipam_user_data[$directory_member]['role'] == 'Administrator') {
                            // Set me back to user
                            $values = array( 
                                "id"             =>$phpipam_user_data[$directory_member]['id'],
                                "role"           =>"User",
                                "widgets"        =>$default_widgets['User'] 
                            );
                        }
                    }
                    if ( array_key_exists("role",$values)) {
                        // Change user role according to set values
                        if (!$Admin->object_modify("users", "edit", "id", $values)) { 
                            $Result->show("danger",  _("Users")." "."edit"." "._("error")."!", false); 
                        }
                        else { 
                            echo "      Role changed to ".$values['role']."\n"; 
                        }
                    }
                }

                // Get data once again (if user was added)
                if ($reload_add_group_member) { 
                    $phpipam_user_data_tmp = $Admin->fetch_multiple_objects ("users", "authMethod", $auth_methodId, $sortField = 'id', $sortAsc = true, $like = false, $result_fields = "*"); 
                    // Make it easier to access
                    $phpipam_user_data = phpipam_user_group_membership_sort($phpipam_user_data_tmp);
                }

                //////////////////////////////////////////////
                // Remove users from group if they are not members of the directory group
                //////////////////////////////////////////////
                foreach ($phpipam_user_data as $phpipam_member) {
                    $user_delete_from_group = 1;
                    foreach($directory_group_members[$group] as $directory_member) {
                        if (!array_key_exists($phpipam_groups[$group]['g_id'], $phpipam_member['groups'])) { $user_delete_from_group = 0; }
                        elseif (array_key_exists($phpipam_groups[$group]['g_id'], $phpipam_member['groups']) and $phpipam_member['username'] == $directory_member ) {
                            $user_delete_from_group = 0;
                        }
                    }
                    if ($user_delete_from_group) {
                        if (!array_key_exists($phpipam_member['username'],$phpipam_current_user_groups)) { $phpipam_current_user_groups[$phpipam_member['username']] = $phpipam_member['groups'];  }
                        // Delete user from phpipam group, which does not belong in it (anymore)
                        //   do it manually again, because the "remove_group_from_user" has a bug (and only removes 1 group each run or so)
                        unset($phpipam_current_user_groups[$phpipam_member['username']][ $phpipam_groups[$group]['g_id'] ]);
                        $new_groups = json_encode($phpipam_current_user_groups[$phpipam_member['username']]);
                        if (!$Admin->object_modify("users", "edit", "id", array("id"=>$phpipam_member['id'], "groups"=>$new_groups))) {
                        //if (!$Admin->remove_group_from_user(strval($phpipam_groups[$group]['g_id']),$phpipam_member['id'])) {
                            $Result->show("danger",  _("Users")." "."'remove user from group'"." "._("error")."!", false); 
                        }
                        else {
                            echo "    ".escape_input($phpipam_member['username']) . " (removed)\n";
                        }
                    }
                }
            }
            else {
                echo "    No members in directory group " . $group . "\n";
            }
            echo "\n";
        }
    } else {
        echo "No Group found in Directory.\n";
    }

    //////////////////////////////////////////////
    // Remove users, which do not exist in the directory anymore
    //////////////////////////////////////////////
    echo "\n";
    echo "--------------------------\n";
    echo "Check for users to remove\n";
    echo "--------------------------\n";
    $message = 1;

    // Get all users in group from phpipam db
    $phpipam_user_data_tmp = $Admin->fetch_multiple_objects ("users", "authMethod", $auth_methodId, $sortField = 'id', $sortAsc = true, $like = false, $result_fields = "*");
    // Make it easier to access
    $phpipam_user_data = phpipam_user_group_membership_sort($phpipam_user_data_tmp);

    foreach ($phpipam_user_data as $phpipam_user) { 
        $user_exists = 0;
        if ($directory_group_members) {
            foreach ($directory_group_members as $directory_group) {
                foreach ($directory_group as $directory_group_member) {
                    if ($phpipam_user['username'] == $directory_group_member) {
                        $user_exists = 1;
                    }
                }
            }
        }
        if (!$user_exists) {
            $message = 0;
            // Remove user from phpipam db
            if (!$Admin->object_modify("users", "delete", "id", array("id"=>$phpipam_user['id']))) { 
                $Result->show("danger",  _("User")." "."delete"." "._("error")."!", false); 
            }
            else { echo $phpipam_user['username']." (removed) \n"; }
        }
    }
    if ($message) { echo "No users to remove\n"; }

    //////////////////////////////////////////////
    // Remove groups, which do not exist in the directory anymore
    //////////////////////////////////////////////
    echo "\n";
    echo "--------------------------\n";
    echo "Check for groups to remove\n";
    echo "--------------------------\n";
    $message = 1;

    foreach ($phpipam_groups as $phpipam_group) {
        $group_exists = 0;
        // wont let me access the f**** key -> lets loop...
        $g_name = "";
        $g_id = "";
        $g_desc = "";
        foreach ($phpipam_group as $schitt=>$schass) {
            if ($schitt == "g_name") { $g_name = $schass; }
            if ($schitt == "g_id")   { $g_id = $schass; }
            if ($schitt == "g_desc")   { $g_desc = $schass; }
        }
        if ($groups) {
            foreach ($groups as $group=>$desc) {
                if ( $g_name ==  $group) { $group_exists = 1; }
            }
        }

        if (!$group_exists and ($g_desc !== '' and str_contains($g_desc,"imported")) ) {
            $message = 0;
            // Remove all group users and sections first
            if (!$Admin->remove_group_from_users($g_id)) { 
                $Result->show("danger",  _("Group")." "."remove from users"." "._("error")."!", false); 
            }
            if (!$Admin->remove_group_from_sections($g_id)) { 
                $Result->show("danger",  _("Group")." "."remove from sections"." "._("error")."!", false); 
            }
            // Delete group
            if (!$Admin->object_modify("userGroups", "delete", "g_id", array("g_id"=>$g_id))) { 
                $Result->show("danger",  _("Group")." "."delete"." "._("error")."!", false); 
            }
            else { echo "  ".$g_name." (imported group removed) \n"; }
        }
    }
    if ($message) { echo "No groups to remove\n"; }

    // Empty line on end
    echo "\n";

} catch (adLDAPException $e) {
    echo $e;
    exit();   
}

exit();
