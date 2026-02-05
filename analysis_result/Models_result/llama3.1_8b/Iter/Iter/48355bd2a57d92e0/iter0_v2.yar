rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 00 B3 A2 FF 55 8B EC E8 ?? ?? ?? ?? FF 15 50 A0 B8 00 }
        $pattern1 = { 64 A1 30 00 00 00 00 8B 40 68 C1 E8 08 A7 01 FF 15 08 A1 B8 00 }
        $pattern2 = { 5A 8B CE E8 ?? ?? ?? ?? 85 C0 00 B3 A2 FF FF 15 50 A0 B8 00 }

    condition:
        any of them
}