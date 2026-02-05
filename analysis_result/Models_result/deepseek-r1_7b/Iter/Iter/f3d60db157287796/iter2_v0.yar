rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific call patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 00 00 00 5B }
        $pattern1 = { 85 C0 74 12 E8 25 F0 00 00 CA 01 0E 66 7F }
        $pattern2 = { 83 F8 74 12 E8 4B F8 FF FF 01 0E 5E 83 }

    condition:
        any of them
}