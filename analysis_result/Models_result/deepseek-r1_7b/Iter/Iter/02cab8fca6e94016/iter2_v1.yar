rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? ?? ?? ?? ?? E8 FC FA FF FF CA 00 EC 83 FF 07 EB 5F ED }
        $pattern1 = { 6A 5B ?? 00 ?? E8 25 05 00 00 00 CA 00 EC 10 8B CE EC E8 74 FA FF FF CA 00 EC 5C }
        $pattern2 = { E8 1C ?? 03 C3 8B 4D 00 00 00 00 00 00 00 00 EB 03 00 EC 62 07 8D 43 01 EA EA DD EB 01 }

    condition:
        any of them
}