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

note: `[ ` and ` ]` &rarr; don't forget the space

## default variables

- `$0`-`$9` &rarr; command line arguments by number
- `$#` &rarr; number of command line arguments (0 is script path)
- `$@` &rarr; list of command line arguments
- `$$` &rarr; process ID
- `$?` &rarr; exit status of the script

note: "$1" for example will indicate to handle the first argument as a string.

## arrays operations

create an modify and array:
```bash
# Method 1: All elements at once
my_array=(apple banana cherry)

# Method 2: Assign elements individually
my_array[0]="apple"
my_array[1]="banana"
my_array[2]="cherry"
```

accessing elements:
```bash
echo "${my_array[0]}"   # Prints "apple"
echo "${my_array[1]}"   # Prints "banana"
```

get all elements as list:
```bash
echo "${my_array[@]}"   # "apple banana cherry"
```

accessing length of array:
```bash
echo "${#my_array[@]}"  # Number of elements in the array
echo "${#my_array[1]}"  # Length of the string "banana" (6)
```

#### Slicing:

Array manipulation syntax:
```bash
#format: ${array[@]:start:length}
echo "${my_array[@]:0:2}"   # "apple banana"

# 1) Using the total length:
n=2
start=$(( ${#my_array[@]} - n ))
echo "${my_array[@]:start:n}"   # Last 2 elements -> "banana cherry"

# 2) Negative offset (Bash >= 4):
echo "${my_array[@]: -2}"       # "banana cherry"
```

String to string methods:
```bash
my_string="Hello World this is Bash"
IFS=' ' read -r -a words <<< "$my_string"

echo "${words[0]}"  # "Hello"
echo "${words[1]}"  # "World"
# ...

```
- `IFS=' '` &rarr; sets **temporarily** the `Internal Field Seperator` to a single space
- `read` &rarr; assign `stdin` to words variable (could be `echo "$string" | read -r -a arr`)
- `-r` &rarr; ignore backslash characters
- `-a words` &rarr; store space-separated token in `"$my_string"` to th element `words`
- `<<< "$my_string"` &rarr; give string through stdin with seperator `IFS` as array, could be `echo "$string" | read -r -a arr`

String manipulation syntax:
```bash

my_string="Hello"
echo "${my_string:0:1}"  # "H" (1st character)
echo "${my_string:1:1}"  # "e" (2nd character)
echo "${my_string:0:2}"  # "He" (first 2 characters)
```


# Operators

In depth [explanation](https://tldp.org/LDP/abs/html/comparison-ops.html) of bash operators.

## string operators

- `==` &rarr; is equal to
- `!=` &rarr; is not equal to
- `<`  &rarr; is less than in ASCII alphabetical order
- `>` &rarr; is greater than in ASCII alphabetical order
- `-z` &rarr; if the string is empty (null)
- `-n` &rarr; if the string is not null

note: String comparison operators "`<` / `>`" works only within the double square brackets [[ ..condition.. ]]. 

## Integer operations

- `-eq` &rarr; is equal to
- `-ne` &rarr; is not equal to
- `-lt` &rarr; is less than
- `-le` &rarr; is less than or equal to
- `-gt` &rarr; is greater than
- `-ge` &rarr; is greater than or equal to

## File operators

- `-e` &rarr; if the file exist
- `-f` &rarr; tests if it is a file
- `-d` &rarr; tests if it is a directory
- `-L` &rarr; tests if it is if a symbolic link
- `-N` &rarr; checks if the file was modified after it was last read
- `-O` &rarr; if the current user owns the file
- `-G` &rarr; if the file’s group id matches the current user’s
- `-s` &rarr; tests if the file has a size greater than 0
- `-r` &rarr; tests if the file has read permission
- `-w` &rarr; tests if the file has write permission
- `-x` &rarr; tests if the file has execute permission

## Boolean and logic

`[[...]` is used for `value` comparison. Whenever you have a bash interpreter, use `[[...]]` to allow `pattern matching` and `regex matching`.

with double braquets (`[[condition1 && condition2]]`):
- `!` &rarr; logical negotation NOT
- `&&` &rarr; logical AND
- `||` &rarr; logical OR

with single braquets (`[condition1 -a condition2]`):
- `-a` &rarr; logical AND 
- `-o` &rarr; logical OR

## Arythmetic operators

```bash
#!/bin/bash

increase=1
decrease=1

echo "Addition: 10 + 10 = $((10 + 10))"
echo "Subtraction: 10 - 10 = $((10 - 10))"
echo "Multiplication: 10 * 10 = $((10 * 10))"
echo "Division: 10 / 10 = $((10 / 10))"
echo "Modulus: 10 % 4 = $((10 % 4))"

((increase++))
echo "Increase Variable: $increase"

((decrease--))
echo "Decrease Variable: $decrease"
```

will give the output:
```
Addition: 10 + 10 = 20
Subtraction: 10 - 10 = 0
Multiplication: 10 * 10 = 100
Division: 10 / 10 = 1
Modulus: 10 % 4 = 2
Increase Variable: 2
Decrease Variable: 0
```

# Script control

## Input

get input with `read`, eg:
```bash
read -p "Select your option: " opt

case $opt in
	"1") network_range ;;
	"2") ping_host ;;
	"3") network_range && ping_host ;;
	"*") exit 0 ;;
esac
```

## Output options

- `echo` &rarr; simple output, many options
- `tee` &rarr; write to file *and* stdout

## Loops

### for loops

```bash
for variable in 1 2 3 4
do
	echo $variable
done

Code: bash

for variable in file1 file2 file3
do
	echo $variable
done

Code: bash

for ip in "10.10.10.170 10.10.10.174 10.10.10.175"
do
	ping -c 1 $ip
done
```

and inline:
`for ip in 10.10.10.170 10.10.10.174;do ping -c 1 $ip;done`

### while loops

```bash
counter=0

while [ $counter -lt 10 ]
do
  # Increase $counter by 1
  ((counter++))
  echo "Counter: $counter"

  if [ $counter == 2 ]
  then
    continue
  elif [ $counter == 4 ]
  then
    break
  fi
done
```

### until loops

The code inside a until loop is executed as long as the particular condition is false.

```bash
counter=0

until [ $counter -eq 10 ]
do
  # Increase $counter by 1
  ((counter++))
  echo "Counter: $counter"
done
```

##  Functions

```bash
#!/bin/bash

function print_pars {
	echo $1 $2 $3
}

one="First parameter"
two="Second parameter"
three="Third parameter"

print_pars "$one" "$two" "$three"
```

### return values from process

- 1 &rarr; General errors
- 2 &rarr; Misuse of shell builtins
- 126 &rarr; Command invoked cannot execute
- 127 &rarr; Command not found
- 128 &rarr; Invalid argument to exit
- 128+n &rarr; Fatal error signal "n"
- 130 &rarr; Script terminated by Control-C
- 255\\* &rarr; Exit status out of range

## Debugging

https://tldp.org/LDP/Bash-Beginners-Guide/html/sect_02_03.html