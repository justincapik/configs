# Bash scripting

Bash scripting basics.

## conditions

format example:
```bash

if [ $value -gt "10" ]
then
    ...
elif [ $value -eq "10" ]
then
    ...
else
    ...
fi

```

notes:
- `[ ` and ` ]` -> don't forget the space
- `-gt`->`>` ... `-eq`->`==` ... `-lt`->`<`

## default variables

- `$0`-`$9` -> command line arguments by number
- `$#` -> number of command line arguments (0 is script path)
- `$@` -> list of command line arguments
- `$$` -> process ID
- `$?` -> exit status of the script