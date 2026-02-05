rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 53 56 57 68 00 40 40 00 E8 90 F6 FF FF CA 00 40 15 A0 }
        $pattern1 = { 83 C4 08 AD 08 85 C0 EA EA 8B 45 08 EA DD EB 08 }
        $pattern2 = { 6A 00 00 00 00 00 E8 6B F3 FF FF CA 00 40 12 C0 53 EB }

    condition:
        any of them
}