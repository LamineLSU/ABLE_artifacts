rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp3=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 }
        $pattern2 = { 8B FF 55 8B EC FF 75 08 }
        $pattern3 = { E8 C8 FF FF FF FF 15 AC B0 41 00 }

    condition:
        any of them
}