rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific calls and conditions"
        cape_options = "bp0=E825050000+0,action0=skip,bp1=7412+2,action1=skip,bp2=0F8433FDFFFF+6,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 00 00 }
        $pattern1 = { 74 12 6A 5B 5A 0F }
        $pattern2 = { 0F 84 33 FD FF FF }

    condition:
        any of them
}