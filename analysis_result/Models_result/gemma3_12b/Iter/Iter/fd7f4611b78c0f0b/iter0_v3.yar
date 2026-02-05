rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 }
        $pattern1 = { E8 C8 FF FF FF 55 8B EC 83 EC ?? 53 56 57 8B 45 ?? }
        $pattern2 = { FF 15 AC B0 41 00 8B 45 ?? 8D 8D F8 FE FF FF 50 E8 E3 FA FF FF }

    condition:
        any of them
}