rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }  // Call -> cmp eax, 01h -> je
        $pattern1 = { E8 F4 2D 68 04 50 E8 F4 2D 68 04 }   // Call-push-call sequence
        $pattern2 = { FF 75 08 E8 94 DB 19 75 }          // Push before ExitProcess call

    condition:
        any of them
}