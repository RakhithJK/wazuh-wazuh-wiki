## Table of Contents  

- [Types and variables](#types-and-variables)
- [Control flow sentences](#control-flow-sentences)
- [Functions](#functions)
- [Formulas](#formulas)
- [Preprocessor definitions](#preprocessor-definitions)

## Types and variables

### Variable declarations

```c
double PI 3.141592653589793238462643383279502884;

int x;
int y;

char * string;
size_t string_len = strlen(string);

char array[50];
const int PRIMES[] = { 2, 3, 5, 7 };
custom_type myvar = { .first_member = 0 };

const char * ERROR_MESSAGES[] {
    [0]      = "No error",
    [EPERM]  = "Operation not permitted",
    [ENOENT] = "No such file or directory"
};
```

#### Hints

- Create well-descriptive names for variables.
- Suggest the type of the variable if necessary.
- Use one line for each variable.
- Use indexes to initialize arrays related to an enumeration.


### Type definition

```c
typedef struct {
    char * name;
    unsigned int enabled:1;
    unsigned int verbose:1;
} mytype_t;

typedef enum { BLACK, WHITE } my_enum;
```

#### Hints

- Put all bitfields together so the compiler will assign the same chunk for all.
- Use multiple lines to declare an enumeration if it contains many values.

## Control flow sentences

### Conditionals

```c
if (ptr == NULL) {
    // Then-part
} else {
    // Else-part
}

if (!is_null) {
    // Then-part
}
```

### Loops

```c
for (int i = 0; i < MAX; i++) {
    // Loop body
}
```

```c
while (condition) {
    // Loop body
}
```

```c
do {
    // Loop body
} while (condition);
```

### Switch

```c
switch (value) {
case 0:
    zero();
    break;

case 1:
case 2:
    low();
    // Fallthrough

case 3:
    positive();
    break;

default:
    high();
}
```

### Hints

- `if`, `for`, `while` and `switch` are control flow sentences, no functions. 
- Put a white-space between the reserved word and the parenthesis, and between the parenthesis and the brace.
- The opening brace should be in the same line as the statement.
- Use the negation operator (`!`) with boolean types only.
- Do not indent the `case` statements inside a `switch`.
- Comment `Fallthrough` if you explicitly want the code falls-through, this will avoid compiler warnings.

## Functions

### Function calls

```c
x = fun(y, 2);
```

### Function definitions

```c
int main(int argc, char * argv[]) {
    // Body
}
```

## Formulas

```c
x = (a + b) / 2 * array[d + e];
y = (a & b) >> 2;
*str++ = '\0`;
```

### Hints

- Use white-spaces in every binary operation.
- Do not use white-spaces in unary operations.
- Use parentheses if and only if they are needed or suggested by the compiler.
- See also: [C operator precedence](https://en.cppreference.com/w/c/language/operator_precedence).

## Preprocessor definitions

```c
#define fun(x) (x * 2)
```