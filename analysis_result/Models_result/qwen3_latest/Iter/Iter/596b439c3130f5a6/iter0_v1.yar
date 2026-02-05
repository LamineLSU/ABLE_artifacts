rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 55 0C FF D0 }
        $pattern1 = { 8B 45 08 8D B0 A0 0C 00 00 EC }
        $pattern2 = { 5A 50 8D B0 A0 0C 00 00 FF D2 }

    condition:
        any of them
}