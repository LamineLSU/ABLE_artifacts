rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 45 8B 45 FF D2 5E 5D C3 } // Combine loop and call instructions
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 } // Call followed by displacement manipulation
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? } // Stack operations and conditional jump

    condition:
        any of them
}