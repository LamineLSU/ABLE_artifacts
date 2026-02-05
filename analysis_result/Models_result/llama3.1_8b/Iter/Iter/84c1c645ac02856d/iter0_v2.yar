rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { 83 C4 14 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern2 = { 41 17 F4 75 18 6F 9B B4 00 }

    condition:
        any of them
}