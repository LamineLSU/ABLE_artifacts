rule "BypassEvadeProtection" : oncall {
    // Pattern 1: Includes push and TEST JZ
    mov $1, [rand:0-255]
    call $1
    test eax
    jz   [rand:-0x7fffffff to 0x7fff]
    
    // Pattern 2: Includes a different conditional jump leading into TEST EAX
    mov $2, [rand:0-255]
    call $2
    cmp    $1, [rand:0-255]
    je     [rand:0x80000000 to 0xFFFFFFFF]
    
    // Pattern 3: Includes a different conditional jump and TEST EAX
    mov $3, [rand:0-255]
    call $3
    cmp    $1, [rand:0-255]
    je     [rand:0x80000000 to 0xFFFFFFFF]
}