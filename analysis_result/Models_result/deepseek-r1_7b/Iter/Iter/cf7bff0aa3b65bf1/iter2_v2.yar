rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF ?? ?? ?? ?? 55 08 }
        $pattern1 = { 75 08 ?? ?? FF FF ?? FF ?? FF FF ?? FF }
        $pattern2 = { FF FF FF FF FF FF FF 75 08 FF FF FF FF }

    condition:
        any of them
}