rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 ?? ?? ?? ?? 50 51 FF D2 }
        $pattern1 = { C3 9A 98 ?? ?? ?? ?? CC E5 1B A4 7E C5 }
        $pattern2 = { 55 8B EC 8B 45 ?? 56 6A 35 6A 00 51 8D B0 ?? ?? ?? ?? ?? 50 E8 74 0A 00 00 }

    condition:
        any of them
}