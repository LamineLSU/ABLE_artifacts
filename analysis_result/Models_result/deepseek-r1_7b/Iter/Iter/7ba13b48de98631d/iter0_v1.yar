rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 EA ?? CA EE CA 01 23 A1 2C }
        $pattern1 = { 85 C0 0F 84 EA ?? CA EE CA 00 31 8C 42 }
        $pattern2 = { 85 C0 0F 84 EA ?? CA EE CA 00 CD A9 DC }

    condition:
        any of them
}