#!/system/bin/env bash

# Partially taken from https://github.com/TeamExodus/frameworks_base
# This script grants the permissions to the OpenGApps on the emulator

PHONE_PERMISSIONS="READ_PHONE_STATE CALL_PHONE READ_CALL_LOG WRITE_CALL_LOG ADD_VOICEMAIL USE_SIP PROCESS_OUTGOING_CALLS"
CONTACTS_PERMISSIONS="READ_CONTACTS WRITE_CONTACTS GET_ACCOUNTS"
LOCATION_PERMISSIONS="ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION"
CALENDAR_PERMISSIONS="READ_CALENDAR WRITE_CALENDAR GET_ACCOUNTS"
SMS_PERMISSIONS="SEND_SMS RECEIVE_SMS READ_SMS RECEIVE_WAP_PUSH RECEIVE_MMS READ_CELL_BROADCASTS"
MICROPHONE_PERMISSIONS="RECORD_AUDIO"
CAMERA_PERMISSIONS="CAMERA"
SENSORS_PERMISSIONS="BODY_SENSORS"
STORAGE_PERMISSIONS="READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE"

grantPerms() {
    for perm in $2; do
        echo ">" pm grant "$1" android.permission."$perm"
        pm grant "$1" android.permission."$perm" 2>/dev/null
    done
}

# Google Account
googleaccountPackage="com.google.android.gsf.login"
grantPerms "$googleaccountPackage" "$CONTACTS_PERMISSIONS"
grantPerms "$googleaccountPackage" "$PHONE_PERMISSIONS"

# Google App
googleappPackage="com.google.android.googlequicksearchbox"
grantPerms "$googleappPackage" "$CALENDAR_PERMISSIONS"
grantPerms "$googleappPackage" "$CAMERA_PERMISSIONS"
grantPerms "$googleappPackage" "$CONTACTS_PERMISSIONS"
grantPerms "$googleappPackage" "$LOCATION_PERMISSIONS"
grantPerms "$googleappPackage" "$MICROPHONE_PERMISSIONS"
grantPerms "$googleappPackage" "$PHONE_PERMISSIONS"
grantPerms "$googleappPackage" "$SMS_PERMISSIONS"
grantPerms "$googleappPackage" "$STORAGE_PERMISSIONS"

# Google Play Services
gmscorePackage="com.google.android.gms"
grantPerms "$gmscorePackage" "$SENSORS_PERMISSIONS"
grantPerms "$gmscorePackage" "$CALENDAR_PERMISSIONS"
grantPerms "$gmscorePackage" "$CAMERA_PERMISSIONS"
grantPerms "$gmscorePackage" "$CONTACTS_PERMISSIONS"
grantPerms "$gmscorePackage" "$LOCATION_PERMISSIONS"
grantPerms "$gmscorePackage" "$MICROPHONE_PERMISSIONS"
grantPerms "$gmscorePackage" "$PHONE_PERMISSIONS"
grantPerms "$gmscorePackage" "$SMS_PERMISSIONS"
grantPerms "$gmscorePackage" "$STORAGE_PERMISSIONS"

# Google Connectivity Services
gcsPackage="com.google.android.apps.gcs"
grantPerms "$gcsPackage" "$CONTACTS_PERMISSIONS"
grantPerms "$gcsPackage" "$LOCATION_PERMISSIONS"

# Google Contacts Sync
googlecontactssyncPackage="com.google.android.syncadapters.contacts"
grantPerms "$googlecontactssyncPackage" "$CONTACTS_PERMISSIONS"

# Google Calendar Sync
googlecontactssyncPackage="com.google.android.syncadapters.calendar"
grantPerms "$googlecontactssyncPackage" "$CALENDAR_PERMISSIONS"

# Google Backup Transport
googlebackuptransportPackage="com.google.android.backuptransport"
grantPerms "$googlebackuptransportPackage" "$CONTACTS_PERMISSIONS"

# Google Play Framework
gsfcorePackage="com.google.android.gsf"
grantPerms "$gsfcorePackage" "$CONTACTS_PERMISSIONS"
grantPerms "$gsfcorePackage" "$PHONE_PERMISSIONS"

# Google Setup Wizard
setupwizardPackage="com.google.android.setupwizard"
grantPerms "$setupwizardPackage" "$CONTACTS_PERMISSIONS"
grantPerms "$setupwizardPackage" "$PHONE_PERMISSIONS"

# Google Play Store
vendingPackage="com.android.vending"
grantPerms "$vendingPackage" "$CONTACTS_PERMISSIONS"
grantPerms "$vendingPackage" "$PHONE_PERMISSIONS"
grantPerms "$vendingPackage" "$LOCATION_PERMISSIONS"
grantPerms "$vendingPackage" "$SMS_PERMISSIONS"
grantPerms "$vendingPackage" "$STORAGE_PERMISSIONS"

exit 0
