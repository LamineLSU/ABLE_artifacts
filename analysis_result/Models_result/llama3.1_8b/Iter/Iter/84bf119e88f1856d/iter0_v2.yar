rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp2=$pattern3+0,action2=skip"

    strings:
        $pattern1 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF }
        $pattern2 = { FF 15 AC B0 41 00 59 FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}