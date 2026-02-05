rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific ExitProcess calls"
        cape_options = "bp0=$pattern0+0,bp1=$pattern1+0,bp2=$pattern2+0,action0=skip,action1=skip,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC }
        $pattern1 = { FF 15 AC B0 41 00 }
        $pattern2 = { E8 C8 FF FF FF }

    condition:
        (any of them)
}