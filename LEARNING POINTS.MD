form data can only be sent along with request body on
 - POST, PUT, PATCH
   - if you would like to send a delete request with an accompanying form, tough luck
     - there are workarounds (in fact many in nodejs) but the better approach should be to follow the specifications
     - According to the RFC:

    The DELETE method requests that the origin server remove the association between the target resource and its current functionality.
    (target resource would mean the resource pointed by the URL)

call http.ResponseWriter.WriteHeader before .Write
 - http.ResponseWriter.Write "closes" the writer for further changes

don't base test result solely on http.StatusOk
 - the default status code is http.StatusOk
   - if your code is leaky it may produce an uncaught http.StatusOk


docker stuff
  - especially for database containers, mount physical volume to container
    - so that when container is destroyed the data persists!
    - watch this series https://www.youtube.com/watch?v=5q-mXycaPBs&list=PLHq1uqvAteVsnMSMVp-Tcb0MSBVKQ7GLg


sql stuff
  - creating custom functions see https://www.youtube.com/watch?v=GNTap3iVg3c
  - creating triggers https://www.youtube.com/watch?v=pO3T7QCVSUI
  - audit trail best practice
    - create a separate table that tracks changes made and log
      - old value, new value
      - item id
      - timestamp
      - user who updated
    - create if statement to check if any fields were change before committing updated
      - IF row(NEW.*) IS DISTINCT FROM row(OLD.*) THEN
          INSERT INTO user_audit (user_audit_id, old_user_email, new_user_email, operation, postgres_user_id)
          VALUES (nextval('custom-sequence'), OLD.email, NEW.email, TG_OP, current_user);
        END IF;
      
