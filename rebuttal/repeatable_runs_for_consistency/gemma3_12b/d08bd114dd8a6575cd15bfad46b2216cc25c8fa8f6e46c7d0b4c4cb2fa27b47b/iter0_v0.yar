rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 36 6A 00 51 50 E8 ?? ?? ?? ?? }
        $pattern1 = { 56 56 6A 36 6A 00 51 51 }
        $pattern2 = { 18 8A 02 55 8B EC 8B 45 08 }

    condition:
        any of them
}