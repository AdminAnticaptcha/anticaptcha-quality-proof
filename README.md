## anticaptcha-quality-proof

Simple PHP script to verify that Anti-Captcha.com Recaptcha solving API is really working.

You will need Linux machine with PHP installed. Script will not work in Windows.

Register random domain at https://www.google.com/recaptcha/admin . Note that you don't have to be the owner of this domain. It can be microsoft.com, trumpsucks.org, whatever.com.
Grab site key, secret key and your Anti-Captcha API access key. Run the script in terminal and enter these values when prompted.

```
git clone git@github.com:AdminAnticaptcha/anticaptcha-quality-proof.git
cd anticaptcha-quality-proof
php recaptcha.php
```
