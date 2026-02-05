rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Skip in al, dx"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 08 8B 48 10 56 6A 35 6A 00 51 }
        $pattern1 = { 8D B0 74 0C 00 00 56 50 }
        $pattern2 = { 8B 55 14 8B 45 10 8B 4D 0C }

    condition:
        any of them
}