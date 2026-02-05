rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 20 7E 07 FF 15 9C 91 44 00 83 F8 ?? 7E ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 FF 15 9C 91 44 00 83 F8 ?? 7E ?? }
        $pattern2 = { 57 53 53 8D 4D 84 E8 EC A7 FF FF 51 8D 4D 84 E8 EC A7 FF FF 85 C0 FF 15 9C 91 44 00 83 F8 ?? 7E ?? }

    condition:
        any of them
}