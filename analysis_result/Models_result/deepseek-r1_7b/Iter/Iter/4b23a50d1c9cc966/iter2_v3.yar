rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 00 00 8B 41 3C ?? ?? ?? ?? 55 ?? }
        $pattern1 = { E8 F7 25 00 00 ?? ?? ?? ?? 83 F8 01 74 20 ?? ?? ?? }
        $pattern2 = { A8 01 02 8B 40 68 C1 E8 08 A8 01 ?? 75 10 ?? }

    condition:
        any of them
}