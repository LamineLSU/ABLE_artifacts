rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4B EA AD AD EA EB 5A EB FF 75 08 DD EB 08 E8 C8 CA DD 00 41 0A }
        $pattern1 = { 8B EB EA AD EB 53 EB FF 75 08 DD EB 08 59 ED FF 75 08 DD EB 08 E8 12 CA DD 00 40 A0 3C }
        $pattern2 = { 8B EC EA AD EB 5A EA FF 75 08 DD EB 08 59 ED FF 75 08 DD EB 08 E8 4B CA DD 00 40 A1 2C }
    condition:
        any of them
}