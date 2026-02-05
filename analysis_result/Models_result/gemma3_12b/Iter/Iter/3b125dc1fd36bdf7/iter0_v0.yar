rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 FF 15 28 A2 41 00 }  //push esi; call dword ptr [0041A228h] - Trace 1
        $pattern1 = { FF 75 08 E8 4E 00 00 00 } //push dword ptr [ebp+08h]; call 0A14ECCCh - Trace 2
        $pattern2 = { 55 8B EC E8 BB 21 00 00 } //push ebp; mov ebp, esp; call 0A150E0Ch - Trace 2

    condition:
        any of them
}