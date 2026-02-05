rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6B C9 8B CE 56 B9 ?? ?? ?? ?? 8D 65 FC }
        $pattern1 = { 33 DB E9 ?? ?? ?? ?? 89 D5 FF D2 }
        $pattern2 = { 83 EC 14 66 3A 01 74 0E }

    condition:
        any of them
}