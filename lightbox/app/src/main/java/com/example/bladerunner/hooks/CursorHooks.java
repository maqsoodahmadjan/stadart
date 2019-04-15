package com.example.bladerunner.hooks;

import android.content.ContentProviderClient;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.provider.ContactsContract;
import android.util.Log;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 11/12/2016.
 */

public class CursorHooks extends GenericHooks{
    public static void parseContacts(ContentResolver contentResolver) {

        String phoneNumber = null;
        String email = null;

        Uri CONTENT_URI = ContactsContract.Contacts.CONTENT_URI;
        String _ID = ContactsContract.Contacts._ID;
        String DISPLAY_NAME = ContactsContract.Contacts.DISPLAY_NAME;

        String HAS_PHONE_NUMBER = ContactsContract.Contacts.HAS_PHONE_NUMBER;
        Uri PhoneCONTENT_URI = ContactsContract.CommonDataKinds.Phone.CONTENT_URI;
        String Phone_CONTACT_ID = ContactsContract.CommonDataKinds.Phone.CONTACT_ID;
        String NUMBER = ContactsContract.CommonDataKinds.Phone.NUMBER;
        Uri EmailCONTENT_URI =  ContactsContract.CommonDataKinds.Email.CONTENT_URI;
        String EmailCONTACT_ID = ContactsContract.CommonDataKinds.Email.CONTACT_ID;
        String DATA = ContactsContract.CommonDataKinds.Email.DATA;
        Uri postal_uri = ContactsContract.CommonDataKinds.StructuredPostal.CONTENT_URI;
        String postalCONTACT_ID = ContactsContract.CommonDataKinds.StructuredPostal.CONTACT_ID;
        String POSTAL = ContactsContract.CommonDataKinds.StructuredPostal.DATA;

        StringBuffer output = new StringBuffer();
        Cursor cursor = OriginalMethod.by(new $() {}).invoke(contentResolver,CONTENT_URI, null,null, null, null);
        // Loop for every contact in the phone

        if (cursor.getCount() > 0) {
            while (cursor.moveToNext()) {
                String contact_id = cursor.getString(cursor.getColumnIndex( _ID ));
                String name = cursor.getString(cursor.getColumnIndex( DISPLAY_NAME ));
                int hasPhoneNumber = Integer.parseInt(cursor.getString(cursor.getColumnIndex( HAS_PHONE_NUMBER )));
                if (hasPhoneNumber > 0) {
                    output.append("\n First Name:" + name);
                    // Query and loop for every phone number of the contact
                    Cursor phoneCursor = OriginalMethod.by(new $() {}).invoke(contentResolver,PhoneCONTENT_URI, null, Phone_CONTACT_ID + " = ?", new String[] { contact_id }, null);
                    while (phoneCursor.moveToNext()) {
                        phoneNumber = phoneCursor.getString(phoneCursor.getColumnIndex(NUMBER));
                        output.append("\n Phone number:" + phoneNumber);
                    }
                    phoneCursor.close();
                    // Query and loop for every email of the contact
                    Cursor emailCursor = OriginalMethod.by(new $() {}).invoke(contentResolver,EmailCONTENT_URI,	null, EmailCONTACT_ID+ " = ?", new String[] { contact_id }, null);
                    while (emailCursor.moveToNext()) {
                        email = emailCursor.getString(emailCursor.getColumnIndex(DATA));
                        output.append("\nEmail:" + email);
                    }
                    emailCursor.close();
                    // Query and loop for every address of the contact
                    Cursor addressCursor = OriginalMethod.by(new $() {}).invoke(contentResolver,postal_uri,	null, postalCONTACT_ID+ " = ?", new String[] { contact_id }, null);
                    while (addressCursor.moveToNext()) {
                        email = addressCursor.getString(addressCursor.getColumnIndex(DATA));
                        output.append("\nAddress:" + email);
                    }
                    addressCursor.close();
                }
                output.append("\n");
            }
            //outputText.setText(output);
        }
    }
    @Hook("android.content.ContentResolver->query")
    public static Cursor ContentResolver_query(ContentResolver cr, Uri uri, String[] projection, String selection,
                                               String[] selectionArgs, String sortOrder) {
        Log.d(TAG, "ContentResolver_query uri "+ uri.toString());
        //content://com.android.contacts/contacts
        if(selection != null)
            Log.d(TAG, "ContentResolver_query selection "+ selection.toString());
        return OriginalMethod.by(new $() {}).invoke(cr,uri,projection, selection, selectionArgs, sortOrder);
    }

/*
    @Hook("android.content.ContentProviderClient->query")
    public static Cursor ContentProviderClient_query(ContentProviderClient cr, Uri uri, String[] projection, String selection,
                                                     String[] selectionArgs, String sortOrder) {
        Log.d(TAG, "ContentProviderClient_query uri "+ uri.toString());
        //content://com.android.contacts/contacts
        if(selection != null)
            Log.d(TAG, "ContentProviderClient_query selection "+ selection.toString());
        return OriginalMethod.by(new $() {}).invoke(cr,uri,projection, selection, selectionArgs, sortOrder);
    }
    */

/*
    @Hook("android.database.AbstractCursor->moveToNext")
    public static boolean Cursor_move(Cursor c) {
        boolean res = false;
        Log.d(TAG,"Cursor_move pos1: " + c.getPosition());
        Log.d(TAG,"Cursor_move count1: " + c.getCount());
        if(c.getPosition() == -1 ||  c.getPosition() < c.getCount() - 1) {
            if(c.getCount() > 0 ) {
                res = OriginalMethod.by(new $() {}).invoke(c);
                String _ID = ContactsContract.Contacts._ID;
                String DISPLAY_NAME = ContactsContract.Contacts.DISPLAY_NAME;
                String name = c.getString(c.getColumnIndex(DISPLAY_NAME));
                Log.d(TAG, "Cursor_move name: " + name);
                Log.d(TAG, "Cursor_move name: " + (name.equals("Lucas")));
                if (name.toString().equals("Lucas") || name.toString().equals("Daniela")
                        || name.toString().equals("Laura")) {
                    Log.d(TAG, "I want to hide " + name);
                    if(c.getPosition() < c.getCount() - 2) {
                        res = OriginalMethod.by(new $() {}).invoke(c);
                    }
                    else return false;
                    _ID = ContactsContract.Contacts._ID;
                    DISPLAY_NAME = ContactsContract.Contacts.DISPLAY_NAME;
                    name = c.getString(c.getColumnIndex(DISPLAY_NAME));
                    Log.d(TAG, "Cursor_move name2: " + name);
                    return res;
                }
                if (name.toString().equals("Marco") ) {
                    Log.d(TAG, "I want to hide " + name);
                    String POSTAL = ContactsContract.CommonDataKinds.StructuredPostal.DATA;
                    String address = c.getString(c.getColumnIndex(POSTAL));
                    if(address != null && address.contains("Svizzera")){
                        res =  OriginalMethod.by(new $() {}).invoke(c);
                    }
                }
            }
        }else{
            Log.d(TAG,"Cursor_move pos2: " + c.getPosition());
            Log.d(TAG,"Cursor_move count2: " + c.getCount());
        }
        return res;
    }
    */
    @Hook("android.database.AbstractCursor->getString")
    public static String Cursor_getString(Cursor c, int i){
        Log.d(TAG,"Cursor_getString: " + i);
        return OriginalMethod.by(new $() {}).invoke(c,i);
    }
}
