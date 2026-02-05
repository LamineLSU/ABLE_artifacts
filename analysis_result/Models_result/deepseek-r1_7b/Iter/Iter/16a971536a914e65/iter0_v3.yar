rule Bypass_Evasion {
    // Rule 0: Bypass after the first function call (E825050000)
    pattern "0" => hex("E825050000", [wildcard] "??" ),

    // Rule 1: Bypass before another function call
    pattern "1" => hex("85C0", [wildcard] "??") | hex("0F8433FDFFFF", wildcard),
    
    // Rule 2: Bypass at the end of a sequence (E9B5FCFFFF)
    pattern "2" => hex("01D6"), 
}