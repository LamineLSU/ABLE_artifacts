rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific sequences targeted"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 8B 41 BA C0 AC }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern2 = { FF 75 08 E8 C8 FF FF FF FF 15 AC B0 41 00 }

    condition:
        any of them
}