rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 83 F8 74 12 8B 4D F8 }
        $pattern1 = { 6A 5B 8B 4F E8 25 05 00 00 }
        $pattern2 = { 5A 0F 84 33 FD FF FF 8E B8 4D }

    condition:
        any of them
}