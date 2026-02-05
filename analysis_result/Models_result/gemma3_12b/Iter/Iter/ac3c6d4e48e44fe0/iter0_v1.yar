rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 81 31 1F 88 A0 28 01 FF 15 }
        $pattern1 = { 6A 40 53 6A 40 53 68 40 11 28 01 }
        $pattern2 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF }

    condition:
        any of them
}