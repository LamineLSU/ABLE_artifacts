rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D B0 A0 0C 00 00 56 50 50 8B 55 0C }
        $pattern1 = { 6A 36 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { 8B 16 50 51 52 5E 5D }

    condition:
        any of them
}