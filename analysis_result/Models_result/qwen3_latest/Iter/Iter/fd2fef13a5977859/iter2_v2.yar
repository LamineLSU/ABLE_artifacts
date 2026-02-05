rule EvasionCheck
{
    meta:
        description = "Detects evasion logic in early execution flow"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
    
    strings:
        $a = { E8 F7 25 00 00 83 F8 01 74 20 }  // Function call and cmp/je
        $b = { C1 E8 08 A8 01 75 10 }             // shr + test al + jne
        $c = { FF 15 3C F1 42 00 }                // Call to GetCurrentProcess

    condition:
        any of them
}