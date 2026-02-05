rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using identified early bypass points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 20 59 00 84 C0 88 EC FF 65 00 00 }  // je followed by call
        $pattern1 = { 8B 40 68 00 0F 84 00 00 8B 45 FC 00 }  // test al, al before call
        $pattern2 = { E8 95 65 FF FF 00 40 D0 35 FF 71 9F 01 00 00 }  // je in second trace

    condition:
        any of them
}