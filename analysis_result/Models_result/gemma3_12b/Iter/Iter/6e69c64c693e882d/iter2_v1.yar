rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF E8 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 55 8B EC 83 EC ?? 53 55 FF 15 AC B0 41 00 }
        $pattern2 = { 8B FF 55 8B EC 83 EC ?? 53 55 FF 15 AC B0 41 00 }

    condition:
        any of them
}