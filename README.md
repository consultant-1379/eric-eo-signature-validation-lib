# ERIC EO SIGNATURE VALIDATION LIB

## Overview

Signature Validation accepts:

    * any type of content
    * signature of content
    * certificate (chain of certificates) to decrypt signature


SignatureService uses TrustStoreService trusted certificates. To initialize TrustStoreService following parameters are mandatory:

    * local file system directory/file, where trusted certificates are stored;
    * flag specifying whether to skip certificate revocation list and key usage extension validation.


In case validation is successful you will be able to proceed with the flow.

In case validation fails the SignatureVerificationException with appropriate message will be thrown.


### How to contribute


Contributions are most welcomed! Just commit your changes, send for review to `HEAD:refs/for/master` and send the review to HoneySkywalkers team

```
git push origin HEAD:refs/for/master
```

