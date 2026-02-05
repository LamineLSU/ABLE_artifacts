rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 FF 15 AC B0 41 00 }  // Skip parameter push and evasion call (11 bytes)
        $pattern1 = { E8 C8 FF FF FF 59 FF 75 08 }  // Skip preparation call and next instructions (11 bytes)
        $pattern2 = { FF 75 08 59 FF 75 08 }  //Skip parameter push and next instructions (9 bytes)

    condition:
        any of them
}