rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific call sequences for evasion"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C1 FF FF FF FF FF 00 }
        $pattern1 = { E8 C1 FF FF FF ?? }
        $pattern2 = { ?? 00 ?? ?? ?? ?? }

    condition:
        any of them
}