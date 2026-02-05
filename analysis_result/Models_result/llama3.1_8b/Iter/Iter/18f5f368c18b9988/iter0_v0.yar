rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 6A 7C 58 68 10 68 26 00 FF }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 F4 }
        $pattern2 = { 6A 7C 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}