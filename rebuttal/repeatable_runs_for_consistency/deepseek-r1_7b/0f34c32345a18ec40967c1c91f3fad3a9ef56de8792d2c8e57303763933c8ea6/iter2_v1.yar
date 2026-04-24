rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific instructions before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern1 = { 8B 45 14 8B 4D 0C 83 E8 00 ?? ?? ?? ?? 74 00 ?? }
        $pattern2 = { 83 F8 01 74 12 00 8B 4D F8 83 E8 00 ?? ?? ?? ?? C3 00 ?? }

    condition:
        any of them
}