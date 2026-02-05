rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 50 E8 CD D3 01 00 42 FE }  // Trace //3:  push ebx; push eax; call 0x42FEB0
        $pattern1 = { 55 8B EC 81 EC 0C 01 00 00 89 45 FC E8 38 EB 00 00 42 39 D0 } // Trace //4: push ebp; mov esp, ebp; sub esp, 0x10c; ...
        $pattern2 = { 55 8B EC 81 EC 0C 01 00 00 89 45 FC E8 38 EB 00 00 42 4D 00 } // Trace //4: push ebp; mov esp, ebp; sub esp, 0x10c; ...

    condition:
        any of them
}