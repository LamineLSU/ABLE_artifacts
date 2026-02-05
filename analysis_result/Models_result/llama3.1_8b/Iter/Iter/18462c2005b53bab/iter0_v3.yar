rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp2=$pattern3+0,action2=skip"

    strings:
        $pattern1 = { E8 C0 ?? ?? ?? ?? 59 FF 75 08 }
        $pattern2 = { FF 15 AC B0 41 00 E8 ?? ?? ?? ?? 59 }
        $pattern3 = { 59 FF 75 08 E8 ?? ?? ?? ?? FF }

    condition:
        any of them
}