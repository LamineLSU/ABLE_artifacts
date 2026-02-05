rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 5E 5D }
        $pattern1 = { 8B 45 08 8B 88 18 0A 00 00 56 6A 36 }
        $pattern2 = { 0C 8B 8B 06 6 83 C4 14 83 C4 14 }

    condition:
        any of them
}