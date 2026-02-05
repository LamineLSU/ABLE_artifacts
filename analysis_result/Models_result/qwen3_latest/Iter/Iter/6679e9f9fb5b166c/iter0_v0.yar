rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 E8 ?? ?? ?? ?? }  // Push 0 + Call ExitProcess
        $pattern1 = { BA 03 00 00 00 E8 ?? ?? ?? ?? }  // Mov edx,3 + Call unknown
        $pattern2 = { 8B 85 9C FD FF FF E8 ?? ?? ?? ?? }  // Mov eax,[ebp-264h] + Call unknown

    condition:
        any of them
}