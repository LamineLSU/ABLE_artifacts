rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 7B 10 85 FF 74 1C }  // mov edi, [ebx+10] | test edi, edi | je
        $pattern1 = { 80 7B 28 01 76 09 }      // cmp byte [ebx+28], 0x01 | jbe
        $pattern2 = { 74 1C E8 F7 FB FF FF }  // je | call (offset varies)

    condition:
        any of them
}