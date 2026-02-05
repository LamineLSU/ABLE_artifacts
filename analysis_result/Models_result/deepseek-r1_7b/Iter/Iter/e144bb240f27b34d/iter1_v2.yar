rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF 59 ?? ?? ?? ?? ?? }  // Includes call and pop instructions
        $pattern1 = { FF 75 08 5A 8B 59 ?? ?? ?? ?? ?? }  // Combines push, mov, and pop
        $pattern2 = { 8B EC 0F C4 E8 ?? ?? }  // Includes mov, push, and call

    condition:
        any of them
}