rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? FF 15 28 43 00 }
        $pattern1 = { 6A 00 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 55 8B EC B9 F8 26 43 00 E8 EE 82 FF FF E8 E0 A2 FF FF }

    condition:
        any of them
}