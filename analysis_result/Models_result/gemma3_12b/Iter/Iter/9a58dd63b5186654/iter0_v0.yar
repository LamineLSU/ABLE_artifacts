rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 75 3A 50 8D }  // trace 0041569B
        $pattern1 = { 6A 3C 8D 85 94 FE FF FF 53 50 }  // trace 00425F49
        $pattern2 = { 55 8B EC 81 EC 0C 01 00 00 }  // trace 00415640

    condition:
        any of them
}