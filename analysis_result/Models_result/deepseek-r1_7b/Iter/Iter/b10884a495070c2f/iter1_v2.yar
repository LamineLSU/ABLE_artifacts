rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 08 ?? ?? ?? ?? E8 ?? 45 C0 04 }
        $pattern1 = { F8 EC F4 FF FF ?? 83 C4 04 ?? FF 74 24 10 ?? F8 FC 00 00 ?? ?? ?? ?? FF 74 24 14 ?? F8 FC 00 00 ?? ?? ?? ?? FF 74 24 18 ?? }
        $pattern2 = { 6A 00 ?? 5A 8B CE ?? E8 EC F4 FF FF ?? 83 C4 04 ?? FF 74 24 10 ?? 83 FF FF FF 74 24 10 ?? FF 15 D8 90 AB 00 ?? }

    condition:
        any of them
}