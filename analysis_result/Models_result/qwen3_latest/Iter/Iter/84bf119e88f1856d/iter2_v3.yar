rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule for detecting call instructions and function prologue"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }  // Relative call with wildcard offset
        $pattern1 = { FF15 ?? ?? ?? ?? } // Indirect call with wildcard address
        $pattern2 = { 55 8BEC FF7508 }   // Standard function prologue

    condition:
        any of them
}