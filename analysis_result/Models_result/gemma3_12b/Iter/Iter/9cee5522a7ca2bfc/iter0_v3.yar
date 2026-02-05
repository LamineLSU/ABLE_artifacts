rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F9 04 72 1A 8B 07 2C 02 75 0F }
        $pattern1 = { 89 03 83 C3 04 EB E2 }
        $pattern2 = { FF 96 2C E0 00 00 83 C7 04 8D 5E FC }

    condition:
        any of them
}