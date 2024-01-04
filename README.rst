================
PHPIPAM_DIRECTORY_SYNC
================

About
============
This script is designed to run in the offical phpipam-www docker image. It's purpose is to sync directory groups and users with PHPIPAM.

.. list-table:: **Behaviour**
    :header-rows: 1

    * - Scenario
      - Behaviour
    * - Group in directory but not in PHPIPAM
      - Group gets created with description "(imported from directory on <timestamp>)" and all members in this group are getting added and created aswell if they dont exist in PHPIPAM.
    * - Group not directory but still in PHPIPAM
      - Group with description "(imported from directory on <timestamp>)" gets deleted and all users which are no longer in any directory group (in PHPIPAM) will be deleted from PHPIPAM.
    * - If user is in $admin_group_name
      - If the user exists the role gets updated to Adminstrator, else user will be create with role Adminstrator.
    * - If user is no longer in $admin_group_name
      - Role will be updated to User.

Compatibility
---------------------
Only tested with Active Directory.

Installation
============

Linux System
-----------------------

``git clone https://github.com/takalele/phpipam_directory_sync``

``cd phpipam_directory_sync``

Change the ``module_path`` path to the path of your PHPIPAM installation, default path is /phpipam.

Set the variables in the script to your use case.

Add the sync_directory_with_phpipam.php as cronjob.


Docker (Offical phpipam-www image)
-----------------------
Clone the git repository to your docker host.

``git clone https://github.com/takalele/phpipam_directory_sync``

Edit your docker-compose file.

.. code-block::

    volumes:
      - /path/to/phpipam_directory_sync/start.sh:/start.sh
      - /path/to/phpipam_directory_sync/sync_directory_with_phpipam.php:/etc/periodic/15min/sync_directory_with_phpipam.php
    command:
      - /bin/sh
      - -c
      - /start.sh

Start the container with ``docker-compose up -d``.

.. list-table:: **Vars**
    :header-rows: 1

    * - Name
      - Description
      - Default value
    * - $module_path
      - Path of the PHPIPAM Installation
      - /phpipam
    * - $auth_method
      - Auth Methode
      - AD
    * - $search_dn
      - Search dn (if empty: base dn will be used)
      - 
    * - $search_group_prefix
      - search_group_prefix (if empty, **all** groups from the directory / search dn will be created)
      - PHPIPPAM\_
    * - $admin_group_name
      - Name of the admin group (all users in this group will get the role Administrator)
      - PHPIPPAM_ADMINS
    * - $date_format
      - Date Format
      - d.m.Y
    * - $lang_id
      - Default language
      - 5 (de_DE); check the PHPIPAM DB for other values like: 1 (en_GB)
    * - $mail_notify
      - Enable email notifications for new created users
      - Yes
    * - mail_changelog
      - Enable email change log
      - Yes
    * - $default_widgets['Administrator']
      - Default widgets for Administrators
      - {"vlan":"1","vrf":"1","pdns":"1","circuits":"1","racks":"1","nat":"1","pstn":"1","customers":"1"}
    * - $default_widgets['User']
      - Default Widgets for Users
      - {"vlan":"1","vrf":"1","pdns":"1","circuits":"1","racks":"1","nat":"1","pstn":"1","customers":"1"}
