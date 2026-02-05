rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 25 05 00 00 } // Test, je, and near call
        $pattern1 = { 85 C0 0F 84 33 FD FF FF }      // Test, je with offset
        $pattern2 = { 50 FF 15 2C A1 EC 00 }         // Push + far call to ExitProcess

    condition:
        any of them
}