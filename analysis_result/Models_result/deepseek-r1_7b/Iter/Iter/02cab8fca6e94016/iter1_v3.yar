rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific exit decision checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B CE EC ?? 00 EC 5E 83 }
        $pattern1 = { 8B CE EC ?? 85 C0 EA EA ?? 74 12 00 EC 61 90 ?? E8 4B 17 00 00 CA 00 EC 44 B9 }
        $pattern2 = { ?? ?? ?? ?? DC ?? 5F ED ?? 5E ?? 33 CD EC EB ?? 5B EB ?? E8 57 26 00 00 CA 00 EC 6C E0 }

    condition:
        any of them
}