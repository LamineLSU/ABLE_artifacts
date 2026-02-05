rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 E8 B4 AE FE FF }  // push 0 + call ExitProcess
        $pattern1 = { 8B 85 94 FD FF FF E8 3D CF FF FF }  // mov+call validation
        $pattern2 = { 8D 85 7C FD FF FF E8 4D B9 FE FF }  // lea+call resource check

    condition:
        any of them
}