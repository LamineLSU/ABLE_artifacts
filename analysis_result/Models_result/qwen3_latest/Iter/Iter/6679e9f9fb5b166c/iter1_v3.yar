rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { BA 03 00 00 00 E8 ?? ?? ?? ?? }
        $pattern1 = { 8B 85 88 FD FF ?? E8 ?? ?? ?? ?? }
        $pattern2 = { 33 C0 E8 ?? ?? ?? ?? }

    condition:
        all of them
}