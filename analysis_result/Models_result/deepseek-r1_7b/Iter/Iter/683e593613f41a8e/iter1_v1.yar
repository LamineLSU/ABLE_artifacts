rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - using identified decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? }
        $pattern1 = { A1 88 85 C0 74 ?? ?? }
        $pattern2 = { E8 5F 26 00 ?? ?? ?? 00 00 01 6C }

    condition:
        any of them
}