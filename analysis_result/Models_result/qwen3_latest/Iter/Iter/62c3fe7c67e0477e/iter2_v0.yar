rule EvasionCheck  
{  
    meta:  
        description = "Detects evasion checks via conditional jumps after test eax, eax and specific call sequences."  
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:  
        $a = { E8 25 05 00 00 } // Call to 0x667F  
        $b = { 85 C0 0F 84 33 FD FF FF } // Test + JE to 0x5E83  
        $c = { E8 74 FA FF FF } // Call to 0x5C17  
        $d = { 85 C0 74 12 6A 5B 5A 8B CE } // Initial test + JE + push/pop  
    condition:  
        ($a and $b) or ($c and $b) or $d  
}