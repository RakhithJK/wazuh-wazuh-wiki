## Table of Contents  

- [Naming conventions](#naming-conventions)
- [Style Conventions](#style-conventions)
- [Initialization](#initialization)
- [Code and Const Correctness](#code-and-const-correctness)
- [Memory Management](#memory-management)
- [Secure Coding](#secure-coding)
- [Best Coding Practices](#best-coding-practices)

## Naming conventions

### Variables, enums and constants
* Use well-descriptive and meaningful names for variables.
* Suggest the type of the variable if necessary.
* Make macro names unique. Avoid simple and common names like: MAX, MIN, AVG due to the fact they can conflict with other package names.
* Constants must use ALL_CAPS_WITH_UNDERSCORES (defines or const variables).
* Use `g_` for global variables, e.g. `g_output_file`
* Use `s_` for static variables local to a function, e.g. `s_internal_map`
* Use descriptive lower case names, separated by underscores, and ending in `_t` for typedefs.
* Enums must use descriptive lower case names separated by underscores. The list of enums must use ALL_CAPS_WITH_UNDERSCORES.
  Example:
    ```c
    typedef enum my_descriptive_enum_t { 
      ENUM_VAL_1 = 1,
      ENUM_VAL_2 = 2
    } my_descriptive_enum_t;
    ```
  Note: Do not add a comma on the last element.

### Structs and methods
* Struct name and its values must use descriptive lower case names separated by underscores. Put all bit fields together so the compiler will assign the same chunk for all. Example:
```c
typedef struct {
    char * name;
    unsigned int enabled:1;
    unsigned int verbose:1;
} my_type_t;
```
* Every new method/function being created must use descriptive lower case names separated by underscores.

### Files and Folders
* Use lower case for new folders being created.
* Use snake case (`new_file.h`) for new files being created.
* Use descriptive related prefix for new files, e.g.: `os_query_manager.h`

## Style Conventions
* Use one line for each variable.
* Use indexes to initialize arrays related to an enumeration.
* `if`, `for`, `while` and `switch` are control flow sentences, no functions. Examples:
  1. Conditionals:
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
  2. Loops:
    ```c
    for (int i = 0; i < MAX; ++i) {
        // Loop body
    }
    
    while (condition) {
        // Loop body
    }
   
    do {
        // Loop body
    } while (condition);
    ```
  3. Switch:
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
* Put a white-space between the reserved word and the parenthesis, and between the parenthesis and the brace.
* The opening brace should be in the same line as the statement.
* Use the negation operator (!) with boolean types only.
* Do not indent the case statements inside a switch.
* Comment `Fallthrough` if you explicitly want the code falls-through, this will avoid compiler warnings.
* Use white-spaces in every binary operation.
* Do not use white-spaces in unary operations.
* Use parentheses if and only if they are needed or suggested by the compiler.
* See also: [C operator precedence](https://en.cppreference.com/w/c/language/operator_precedence).
* Functions should limit themselves to a single page of code due to the fact that each method represents a technique for achieving a single objective.
* Avoid using magic numbers. Declare and use a well descriptive macro or constant name instead.

## Initialization
* Always initialize variables. gcc with the flag `-W` may catch operations on uninitialized variables, but it may also not.
* Every pointer being declared must be initialized. If the value of it is not yet defined, `NULL` should be used. This will avoid future memory errors which, in most cases, are very tough to be found.

## Code and Const Correctness
* Use `const` for any object whose value does not change.
* Use `const` for parameters passed by value.
* Return values must be checked to handle errors reasonably. System calls and library functions provide important information to the programmer via return values.
* Include the system error text for every system error message.

## Memory Management
* Every dynamically allocated memory (using `malloc` for instance) must have an associated code to free this memory at some other point in the program.
* Every call to `malloc`, `calloc` or `realloc` must be checked to avoid using memory badly reserved.

## Secure Coding
A simple coding error can lead to a hacking threat.
* Pointers nullness should be checked always unless it's being used in an internal function where it's safe to dereference or when the caller ensures that the pointer is not null.
* When a pointer needs to be freed, always set it to NULL after freeing it. This will avoid double free errors.
Example:
    ```c       
    free(x);
    x = NULL;
    ```
* Always use safe functions instead of insecure ones. This will prevent collateral issues like buffer overflows.

| **Insecure**     | **Safe**      |
| -------------    | ------------- |
| strcpy           | strncpy       |
| strcat           | strncat       |
| printf / sprintf | snprintf      |
| gets             | fgets         |
| tmpfile / mktemp | mkstemp       |

## Best Coding Practices
* A variable must be declared in the inner scope possible.
* Define functions either static or inline if their purpose is to be used only in the .c file.
* Always use defensive programming, checking all values/content before using them, array limits, etc.
