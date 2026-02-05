rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 08 8B 48 14 56 6A 35 6A 00 51 8D B0 A0 0A 00 00 }
        $pattern1 = { 8B 45 08 8B 88 BC 00 00 00 56 6A 36 6A 00 51 8D B0 A8 0A 00 00 }
        $pattern2 = { FF D0 }

    condition:
        any of them
}